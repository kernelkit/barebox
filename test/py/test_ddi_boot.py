# SPDX-License-Identifier: GPL-2.0-or-later

import json
import lzma
import os
import platform
import pytest
import shutil
import struct
import uuid
import zlib

from .helper import skip_disabled
from .test_ddi import gpt_partitions

# Discoverable Partitions Specification type GUIDs of the root, verity
# and verity signature partitions, per architecture
DPS_ROOT = {
    "x86-64": ("4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
               "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5",
               "41092b05-9fc8-4523-994f-2def0408b176"),
    "x86": ("44479540-f297-41b2-9af7-d131d5f0458a",
            "d13c5d3b-b5d1-422a-b29f-9454fdc89d76",
            "5996fc05-109c-48de-808b-23fa0830b676"),
    "arm64": ("b921b045-1df0-41c3-af44-4c6f280d3fae",
              "df3300ce-d69f-4c92-978c-9bfb0f38d820",
              "6db69de6-29f4-4758-a7a5-962190f00ce3"),
    "arm": ("69dad710-2ce4-4e3c-b16c-21a1d49abed3",
            "7386cdf2-203c-47a9-a498-f2ecce45a2d6",
            "42b0455f-eb11-491d-98d3-56145ba9d037"),
    "riscv64": ("72ec70a6-cf74-40e6-bd49-4bda08e8f224",
                "b6ed5582-440b-4209-b8da-5ff7c419ea3d",
                "efe0f087-ea8d-4469-821a-4c2a96a8386a"),
    "riscv32": ("60d5a7fe-8e7d-435c-b714-3dd8162144e1",
                "ae0253be-1167-4007-ac68-43926c14c5de",
                "3a112a75-8729-4380-b4cf-764d79934448"),
}


def barebox_arch(config):
    if config.get("CONFIG_SANDBOX"):
        return {"x86_64": "x86-64", "aarch64": "arm64"}.get(platform.machine())
    if config.get("CONFIG_ARM64"):
        return "arm64"
    if config.get("CONFIG_ARM"):
        return "arm"
    if config.get("CONFIG_X86_64"):
        return "x86-64"
    if config.get("CONFIG_X86"):
        return "x86"
    if config.get("CONFIG_RISCV"):
        return "riscv64" if config.get("CONFIG_64BIT") else "riscv32"
    return None


def gpt_retype(disk, retype):
    """Change the partition type GUIDs of the primary and backup GPTs

    retype maps old to new type GUIDs, both given as uuid.UUID.
    """
    disk = bytearray(disk)
    retype = {old.bytes_le: new.bytes_le for old, new in retype.items()}

    for hdr_lba in (1, len(disk) // 512 - 1):
        hoff = hdr_lba * 512
        assert disk[hoff:hoff + 8] == b"EFI PART", "Missing GPT header"

        hsize, = struct.unpack_from("<I", disk, hoff + 12)
        entries, nentries, entsize = struct.unpack_from("<QII", disk, hoff + 72)

        eoff = entries * 512
        for i in range(nentries):
            ent = eoff + i * entsize
            new = retype.get(bytes(disk[ent:ent + 16]))
            if new:
                disk[ent:ent + 16] = new

        crc = zlib.crc32(disk[eoff:eoff + nentries * entsize])
        struct.pack_into("<I", disk, hoff + 88, crc)

        struct.pack_into("<I", disk, hoff + 16, 0)
        crc = zlib.crc32(disk[hoff:hoff + hsize])
        struct.pack_into("<I", disk, hoff + 16, crc)

    return bytes(disk)


@pytest.fixture(scope="module")
def ddi_disks(testfs, barebox_config):
    """Retype the checked in DDI for the target architecture, and
    create a copy of it whose root hash signature has been tampered
    with. The image was created using systemd-repart, see
    scripts/ddi-verity.sh.
    """
    arch = barebox_arch(barebox_config)
    if arch not in DPS_ROOT:
        pytest.skip("unknown DPS architecture")

    testdata = os.path.join(os.path.dirname(__file__), os.pardir, "testdata")
    path = os.path.join(testfs, "ddi-boot")
    os.makedirs(path, exist_ok=True)

    with lzma.open(os.path.join(testdata, "ddi-verity.disk.xz")) as f:
        disk = f.read()

    disk = gpt_retype(disk, {
        uuid.UUID(old): uuid.UUID(new)
        for old, new in zip(DPS_ROOT["x86-64"], DPS_ROOT[arch])
    })

    parts = {name: (start, size) for name, start, size in gpt_partitions(disk)}
    start, size = parts["root-verity-sig"]
    doc = json.loads(disk[start:start + size].rstrip(b"\0"))
    rh = doc["rootHash"]
    doc["rootHash"] = ("1" if rh[0] == "0" else "0") + rh[1:]
    bad = (disk[:start] + json.dumps(doc).encode().ljust(size, b"\0") +
           disk[start + size:])

    # Wrap the disks in linear mappings, to get block devices
    for name, data in (("good.disk", disk), ("bad.disk", bad)):
        with open(os.path.join(path, name), "wb") as f:
            f.write(data)
        with open(os.path.join(path, f"{name}.dm"), "w") as f:
            f.write(f"0 {len(data) // 512} linear {name} 0\n")

    shutil.copy(os.path.join(testdata, "ddi-verity-ca.pem"),
                os.path.join(path, "ca.pem"))

    yield {
        "path": path,
        "roothash": rh,
    }

    shutil.rmtree(path)


@pytest.fixture(autouse=True)
def cleanup(barebox, barebox_config):
    skip_disabled(barebox_config,
                  "CONFIG_BOOT_DDI",
                  "CONFIG_CMD_KEYS",
                  "CONFIG_CMD_DMSETUP")
    yield
    barebox.run("global.loglevel=6")
    barebox.run("global.ddi.require_trust=1")
    barebox.run("dmsetup remove ddi-good")
    barebox.run("dmsetup remove ddi-bad")
    barebox.run("cd")


def setup_disks(barebox):
    barebox.run_check("cd /mnt/9p/testfs/ddi-boot")
    barebox.run_check("keys -a ddi-boot-test ca.pem")
    barebox.run_check("global.ddi.keyring=ddi-boot-test")
    barebox.run_check("dmsetup create ddi-good good.disk.dm")
    barebox.run_check("dmsetup create ddi-bad bad.disk.dm")


def test_ddi_boot_list(barebox, ddi_disks):
    setup_disks(barebox)

    out = "\n".join(barebox.run_check("boot -l ddi-good ddi-bad"))
    assert "DDI on ddi-good" in out
    assert "DDI on ddi-bad" in out

    # The boot entry inside the root filesystem is only reachable
    # through dm-verity, never by mounting the partition directly
    assert "loader/entries" not in out


def test_ddi_boot_dryrun(barebox, ddi_disks):
    setup_disks(barebox)

    # The dummy kernel can't be booted, but everything up to that
    # point is logged
    barebox.run_check("global.loglevel=7")
    out, _, _ = barebox.run("boot -d -v ddi-bad ddi-good", timeout=120)
    out = "\n".join(out)

    assert "ddi-bad: root hash signature verification failed" in out
    assert "ddi-good: root hash vouched for by" in out
    assert f"roothash={ddi_disks['roothash']}" in out
    assert "booting DDI test" in out

    # No trace of the attempts are left behind
    out = barebox.run_check("ls /dev")
    assert not any(" root " in f" {line} " for line in out)

    # Only the configured keyring is trusted
    barebox.run_check("global.ddi.keyring=nosuchkeyring")
    out, _, returncode = barebox.run("boot -d -v ddi-good", timeout=60)
    assert returncode != 0
    assert "booting DDI test" not in "\n".join(out)
    barebox.run_check("global.ddi.keyring=ddi-boot-test")


def test_ddi_boot_untrusted(barebox, ddi_disks):
    setup_disks(barebox)

    # Without a usable keyring, DDIs are only booted if trust is not
    # required
    barebox.run_check("global.ddi.keyring=nosuchkeyring")
    barebox.run_check("global.ddi.require_trust=0")
    barebox.run_check("global.loglevel=7")
    out, _, _ = barebox.run("boot -d -v ddi-bad ddi-good", timeout=120)
    out = "\n".join(out)

    assert "ddi-good: booting with untrusted root hash" in out
    assert f"roothash={ddi_disks['roothash']}" in out
    assert "booting DDI test" in out

    # dm-verity still verifies the root filesystem against the
    # unverified root hash, so the tampered one can not be mounted
    assert "ddi-bad: booting with untrusted root hash" in out
    assert "ddi-bad: failed to mount root filesystem" in out

    out = barebox.run_check("ls /dev")
    assert not any(" root " in f" {line} " for line in out)
