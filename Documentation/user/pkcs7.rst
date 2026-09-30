.. _pkcs7:

PKCS#7 Signatures and Discoverable Disk Images
==============================================

barebox can verify detached PKCS#7 (CMS) signatures against a set of
trusted X.509 certificates, and use that to verify the root hash
signatures of `Discoverable Disk Images`_ (DDIs), as created by e.g.
``systemd-repart``.

.. _Discoverable Disk Images: https://uapi-group.org/specifications/specs/discoverable_partitions_specification/

The implementation of the X.509 and PKCS#7 parsers is imported from Linux.
Signatures are verified using the same RSA (PKCS#1 v1.5) and ECDSA (P-256
and P-384) implementations that are used for FIT images.

Keyrings
--------

Trusted keys are organized in named keyrings. A signature is accepted if it
was made by a key in the keyring, or by a certificate that chains up to one,
using the certificates carried in the signature. Keyrings can be nested, in
which case all keys of the sub-keyring are trusted wherever the outer
keyring is trusted.

There are three sources of keys:

Compiled in certificates
  Certificates listed in ``CONFIG_CRYPTO_PUBLIC_KEYS`` are compiled into
  barebox, with the same syntax as keys for FIT image verification, e.g.:

  .. code-block:: none

    CONFIG_CRYPTO_PUBLIC_KEYS="keyring=os:/path/to/os-ca.pem"

Certificate files
  Certificates, in PEM or DER format, can be added to a keyring at runtime,
  which is created if it does not exist:

  .. code-block:: sh

    keys -a os /mnt/data/os-ca.pem

  Note that the keys in such a keyring are only as trustworthy as the file
  they were loaded from.

The EFI signature database
  With ``CONFIG_CRYPTO_EFI_DB``, when running as an EFI payload, the
  certificates in the ``db`` variable are loaded into the ``@efi``
  keyring. This only happens when the platform is in Secure Boot user
  mode (``SecureBoot=1``, ``SetupMode=0``), as ``db`` may otherwise have
  been modified by anyone.

  The ``@efi`` keyring can be linked into another keyring, if both should
  be trusted:

  .. code-block:: sh

    keys -l os @efi

The keyrings, and the keys in them, can be listed with the
:ref:`keys command <command_keys>`.

Digests
-------

In addition to keys, keyrings can vouch for data by its SHA256 digest,
without any signature. The SHA256 digests in the EFI ``db`` variable
(``EFI_CERT_SHA256``) are used this way. For files, the digest of the
file is compared, and for DDIs, the root hash.

There is also a global blacklist of digests, which always causes data to
be rejected, whatever the signature. The EFI ``dbx`` variable is loaded
into the blacklist, regardless of the Secure Boot state, since it can only
ever make verification stricter:

- ``EFI_CERT_SHA256``: data, or DDI root hashes, which are rejected.
- ``EFI_CERT_X509``: certificates that are revoked. They are never trusted,
  neither as a trust anchor, nor as part of a chain.
- ``EFI_CERT_X509_SHA256``: the SHA256 of the TBSCertificate of revoked
  certificates.

Verifying files
---------------

The :ref:`pkcs7 command <command_pkcs7>` verifies a detached, DER encoded,
signature of a file:

.. code-block:: sh

  openssl cms -sign -binary -in rootfs.squashfs -signer signer.pem \
          -inkey signer.key -outform DER -out rootfs.squashfs.p7s

.. code-block:: sh

  pkcs7 verify os rootfs.squashfs rootfs.squashfs.p7s

The file is digested piecewise, so it may be arbitrarily large. Signatures
with and without authenticated attributes, with and without embedded
certificates, and with signers identified by issuer and serial number or by
subjectKeyIdentifier are supported.

Verifying Discoverable Disk Images
----------------------------------

A DDI stores the root hash of each dm-verity protected partition, along
with a signature of it, in a ``*-verity-sig`` partition. The ``verify-ddi``
command verifies the signature, and stores the root hash in a variable,
which is then used to set up the verity device:

.. code-block:: sh

  pkcs7 -s roothash verify-ddi @efi /dev/disk0.root-verity-sig
  veritysetup open /dev/disk0.root root /dev/disk0.root-verity $roothash
  mount /dev/root

Since the root hash is only taken from the verified signature document, and
the root filesystem is only accessed through the verity device, every block
read from it is verified against the signed root hash.

Booting Discoverable Disk Images
--------------------------------

With ``CONFIG_BOOT_DDI``, disks holding a root partition, its verity hash
partition, and the verity signature partition, all of the native
architecture, are offered as boot entries. They can be booted like any
other device, listed with ``boot -l``, picked from ``boot -m``, and used as
bootchooser targets:

.. code-block:: sh

  global.ddi.keyring=os
  boot -l internal-primary
  boot internal-primary internal-secondary

Booting such an entry:

1. Verifies the root hash signature against the keyring named by
   ``global.ddi.keyring`` (``os`` by default).
2. Opens the root filesystem through dm-verity, as the device ``root``, and
   mounts it.
3. Boots the first working Boot Loader Specification entry found in it,
   adding the verified root hash to the kernel command line using the
   parameters understood by ``systemd-veritysetup-generator``:

   .. code-block:: none

     roothash=<hash> systemd.verity_root_data=PARTUUID=<root>
     systemd.verity_root_hash=PARTUUID=<root-verity>

   Entries using ``linux-appendroot`` get ``root=/dev/mapper/root``.

With ``global.ddi.require_trust`` (enabled by default) cleared, e.g. when
Secure Boot is disabled, a DDI whose root hash signature can not be
verified is booted anyway. Its root hash is then taken from the signature
document as is, so dm-verity still detects corruption, but not tampering:

.. code-block:: sh

  [ "$efi.secure_boot" = 0 ] && global.ddi.require_trust=0

Should any step fail, the verity device is removed again, and the next
entry is tried. The root partition itself is never scanned for boot
entries by other means, since its contents must only be accessed through
dm-verity.

Security considerations
-----------------------

- Verification done by scripts is only effective if the script itself, and
  the rest of the environment, can not be modified by an attacker, see
  :ref:`security`.

- dm-verity devices are only considered signed, which is what
  ``global.fs.require_signed_backingstore`` requires of mounted devices, if
  their root hash has been vouched for, e.g. by ``pkcs7 verify-ddi`` or by
  booting a DDI.

- There is no reliable time source in barebox, so certificate validity
  periods are not checked. The signing time of a signature, if present, is
  however checked against the validity period of the signer's certificate.

- Key usage restrictions (e.g. the keyUsage and extendedKeyUsage extensions)
  are not enforced; any certificate in a trusted chain may sign data.

- ``CONFIG_CRYPTO_EFI_DB_INSECURE`` makes the ``@efi`` keyring trust
  ``db`` even when Secure Boot is not enforced. It must not be used in
  production.
