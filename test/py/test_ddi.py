# SPDX-License-Identifier: GPL-2.0-or-later

import json
import lzma
import os
import pytest
import shutil
import struct

from .helper import skip_disabled


def gpt_partitions(disk):
    """Yield (name, first byte, size in bytes) of each partition"""
    hdr = disk[512:1024]
    assert hdr[:8] == b"EFI PART", "Missing GPT header"

    entries, nentries, entsize = struct.unpack_from("<QII", hdr, 72)
    for i in range(nentries):
        ent = disk[entries * 512 + i * entsize:][:entsize]
        if ent[:16] == b"\0" * 16:
            continue

        first, last = struct.unpack_from("<QQ", ent, 32)
        name = ent[56:128].decode("utf-16-le").rstrip("\0")
        yield name, first * 512, (last - first + 1) * 512


@pytest.fixture(scope="module")
def ddi_testdata(testfs):
    """Split the checked in DDI into its partitions

    The disk image was created using systemd-repart, see
    scripts/ddi-verity.sh.
    """
    testdata = os.path.join(os.path.dirname(__file__), os.pardir, "testdata")
    path = os.path.join(testfs, "ddi")
    os.makedirs(path, exist_ok=True)

    with lzma.open(os.path.join(testdata, "ddi-verity.disk.xz")) as f:
        disk = f.read()

    for name, start, size in gpt_partitions(disk):
        with open(os.path.join(path, name), "wb") as f:
            f.write(disk[start:start + size])

        # dm-verity operates on block devices, so wrap the data and
        # hash partitions in linear mappings, which is the equivalent
        # of `losetup`.
        with open(os.path.join(path, f"{name}.dm"), "w") as f:
            f.write(f"0 {size // 512} linear {name} 0\n")

    for cert in ("ca", "other"):
        shutil.copy(os.path.join(testdata, f"ddi-verity-{cert}.pem"),
                    os.path.join(path, f"{cert}.pem"))

    # A signature document whose root hash has been tampered with
    with open(os.path.join(path, "root-verity-sig"), "rb") as f:
        sig = f.read()

    doc = json.loads(sig.rstrip(b"\0"))
    rh = doc["rootHash"]
    doc["rootHash"] = ("1" if rh[0] == "0" else "0") + rh[1:]
    with open(os.path.join(path, "root-verity-sig.tampered"), "wb") as f:
        f.write(json.dumps(doc).encode().ljust(len(sig), b"\0"))

    yield {
        "path": path,
        "roothash": rh,
    }

    shutil.rmtree(path)


@pytest.fixture(autouse=True)
def cleanup(barebox, barebox_config):
    skip_disabled(barebox_config,
                  "CONFIG_CMD_PKCS7",
                  "CONFIG_CRYPTO_VERITY_SIG",
                  "CONFIG_CMD_KEYS",
                  "CONFIG_CMD_VERITYSETUP",
                  "CONFIG_CMD_DMSETUP")
    yield
    barebox.run("global.fs.require_signed_backingstore=0")
    barebox.run("umount /mnt/ddi-root")
    barebox.run("veritysetup close ddi-root")
    barebox.run("dmsetup remove ddi-data")
    barebox.run("dmsetup remove ddi-hash")
    barebox.run("cd")


def test_ddi_unverified(barebox, ddi_testdata):
    """A root hash that has not been vouched for does not make the
    verity device signed, even though it is the correct one.

    This must run before any test that verifies the signature.
    """
    barebox.run_check("cd /mnt/9p/testfs/ddi")
    barebox.run_check("dmsetup create ddi-data root.dm")
    barebox.run_check("dmsetup create ddi-hash root-verity.dm")
    barebox.run_check("veritysetup open /dev/ddi-data ddi-root /dev/ddi-hash "
                      + ddi_testdata["roothash"])

    barebox.run_check("global.fs.require_signed_backingstore=1")
    _, _, returncode = barebox.run("mount ddi-root")
    assert returncode != 0, "Unverified verity device should not be mountable"


def test_ddi_verity(barebox, ddi_testdata):
    barebox.run_check("cd /mnt/9p/testfs/ddi")
    barebox.run_check("keys -a ddi-test ca.pem")

    # Since commands run in a subshell, export the root hash in a
    # global, so that we can access it from subsequent commands
    barebox.run_check("global ddi_roothash")
    barebox.run_check("pkcs7 -s global.ddi_roothash verify-ddi ddi-test root-verity-sig")
    rh = barebox.run_check("echo $global.ddi_roothash")[0].strip()
    assert rh == ddi_testdata["roothash"], "Unexpected root hash"

    barebox.run_check("dmsetup create ddi-data root.dm")
    barebox.run_check("dmsetup create ddi-hash root-verity.dm")
    barebox.run_check("veritysetup open /dev/ddi-data ddi-root /dev/ddi-hash $global.ddi_roothash")

    # The root hash has been vouched for, so the device is signed
    barebox.run_check("global.fs.require_signed_backingstore=1")
    barebox.run_check("mount ddi-root")

    out = barebox.run_check("cat /mnt/ddi-root/hello.txt")
    assert out == ["Hello from a verified DDI"]


def test_ddi_untrusted(barebox, ddi_testdata):
    barebox.run_check("cd /mnt/9p/testfs/ddi")
    barebox.run_check("keys -a ddi-other other.pem")

    _, _, returncode = barebox.run("pkcs7 verify-ddi ddi-other root-verity-sig")
    assert returncode != 0, "Signature should not be trusted"


def test_ddi_tampered(barebox, ddi_testdata):
    barebox.run_check("cd /mnt/9p/testfs/ddi")
    barebox.run_check("keys -a ddi-test ca.pem")

    _, _, returncode = barebox.run("pkcs7 verify-ddi ddi-test root-verity-sig.tampered")
    assert returncode != 0, "Tampered root hash should be rejected"
