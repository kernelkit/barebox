#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Create a Discoverable Disk Image holding a dm-verity protected root
# filesystem, whose root hash is signed by a certificate issued by a
# test CA. The root filesystem holds a Boot Loader Specification entry.
# This is used by the DDI labgrid tests.
#
# Partitions are typed for the architecture of the host, the tests
# retype them as needed.
#
#   scripts/ddi-verity.sh test/testdata
#
# Produces:
#   ddi-verity.disk.xz	The disk image
#   ddi-verity-ca.pem	The CA that issued the signing certificate
#   ddi-verity-other.pem	An unrelated certificate

set -e

out=$(realpath "$1")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

ossl() {
	openssl "$@" 2>/dev/null
}

ossl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
     -subj "/O=barebox/CN=ddi-ca" -days 36500
ossl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout signer.key -out signer.csr -subj "/O=barebox/CN=ddi-signer"
ossl x509 -req -in signer.csr -CA ca.pem -CAkey ca.key -set_serial 1 \
     -days 36500 -out signer.pem
ossl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem \
     -subj "/O=barebox/CN=ddi-other" -days 36500

mkdir -p defs root/boot root/loader/entries
echo "Hello from a verified DDI" >root/hello.txt

# A boot entry, whose kernel is only good enough for dry runs
head -c 4096 /dev/zero >root/boot/vmlinuz
cat >root/loader/entries/ddi-test.conf <<EOF
title		DDI test
version		1
linux		/boot/vmlinuz
options		ddi.test
EOF

cat >defs/00-root.conf <<EOF
[Partition]
Type=root
Label=root
Format=vfat
CopyFiles=/
Verity=data
VerityMatchKey=root
SizeMinBytes=1M
SizeMaxBytes=1M
EOF

cat >defs/01-root-verity.conf <<EOF
[Partition]
Type=root-verity
Label=root-verity
Verity=hash
VerityMatchKey=root
SizeMinBytes=128K
SizeMaxBytes=128K
EOF

cat >defs/02-root-verity-sig.conf <<EOF
[Partition]
Type=root-verity-sig
Label=root-verity-sig
Verity=signature
VerityMatchKey=root
EOF

systemd-repart --offline=yes --empty=create --size=auto \
	       --root="$tmp/root" --definitions="$tmp/defs" \
	       --private-key=signer.key --certificate=signer.pem \
	       --dry-run=no ddi-verity.disk

xz -9 <ddi-verity.disk >"$out/ddi-verity.disk.xz"
cp ca.pem "$out/ddi-verity-ca.pem"
cp other.pem "$out/ddi-verity-other.pem"
