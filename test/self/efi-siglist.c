// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/byteorder.h>
#include <bselftest.h>
#include <digest.h>
#include <crypto/efi-siglist.h>
#include <crypto/pkcs7.h>
#include <crypto/sha.h>
#include <crypto/x509.h>
#include <efi/types.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <string.h>
#include <xfuncs.h>

#include "pkcs7-data.h"

BSELFTEST_GLOBALS();

#define EFI_CERT_SHA256_GUID \
	EFI_GUID(0xc1c41626, 0x504c, 0x4092, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28)
#define EFI_CERT_X509_GUID \
	EFI_GUID(0xa5c059a1, 0x94e4, 0x4aa7, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72)
#define EFI_CERT_X509_SHA256_GUID \
	EFI_GUID(0x3bd2a492, 0x96c0, 0x4079, 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed)
#define UNKNOWN_GUID \
	EFI_GUID(0x01234567, 0x89ab, 0xcdef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef)

#define OWNER_GUID \
	EFI_GUID(0x11111111, 0x2222, 0x3333, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55)

struct siglist {
	u8 *buf;
	size_t len;
};

/* Append an EFI_SIGNATURE_LIST holding a single element */
static void siglist_add(struct siglist *sl, efi_guid_t type,
			const void *data, size_t len)
{
	efi_guid_t owner = OWNER_GUID;
	size_t esize = sizeof(owner) + len;
	size_t lsize = sizeof(type) + 3 * sizeof(u32) + esize;
	u32 hdr[3] = { cpu_to_le32(lsize), 0, cpu_to_le32(esize) };
	u8 *p;

	sl->buf = xrealloc(sl->buf, sl->len + lsize);
	p = sl->buf + sl->len;
	sl->len += lsize;

	memcpy(p, &type, sizeof(type));
	p += sizeof(type);
	memcpy(p, hdr, sizeof(hdr));
	p += sizeof(hdr);
	memcpy(p, &owner, sizeof(owner));
	p += sizeof(owner);
	memcpy(p, data, len);
}

static void sha256(const void *data, size_t len, u8 *out)
{
	struct digest *d = digest_alloc_by_algo(HASH_ALGO_SHA256);

	digest_digest(d, data, len, out);
	digest_free(d);
}

static void keyring_free_certs(struct keyring *kr)
{
	struct keyring_link *link, *tmp;
	struct keyring_hash *h, *htmp;

	list_for_each_entry_safe(link, tmp, &kr->links, node) {
		const struct x509_certificate *cert = link->key->cert;

		list_del(&link->node);
		free(link);
		x509_free_certificate((struct x509_certificate *)cert);
	}

	list_for_each_entry_safe(h, htmp, &kr->hashes, node) {
		list_del(&h->node);
		free(h);
	}
}

#define verify(_sig, _kr)						\
	pkcs7_verify_buf(_sig, sizeof(_sig), data, strlen(data), _kr, NULL)

static void test_efi_db(void)
{
	struct keyring db = {
		.name = "efi-siglist-selftest",
		.links = LIST_HEAD_INIT(db.links),
		.hashes = LIST_HEAD_INIT(db.hashes),
	};
	struct siglist sl = {};
	u8 digest[SHA256_DIGEST_SIZE];
	u8 junk[64] = {};

	siglist_add(&sl, EFI_CERT_X509_GUID, root_der, sizeof(root_der));
	siglist_add(&sl, UNKNOWN_GUID, junk, sizeof(junk));
	sha256(data, strlen(data), digest);
	siglist_add(&sl, EFI_CERT_SHA256_GUID, digest, sizeof(digest));
	siglist_add(&sl, EFI_CERT_X509_GUID, rogue_der, sizeof(rogue_der));

	if (!assert_inteq(efi_siglist_load_db(&db, sl.buf, sl.len), 0))
		goto out;

	assert_inteq(verify(sig_noattr, &db), 0);
	assert_inteq(verify(sig_rogue, &db), 0);

	/* Anything with the right digest is accepted */
	assert_inteq(pkcs7_verify_buf(NULL, 0, data, strlen(data), &db, NULL), 0);
	assert_inteq(pkcs7_verify_buf(NULL, 0, data, 3, &db, NULL), -ENOKEY);

	/* Loading the same list again adds nothing */
	assert_inteq(efi_siglist_load_db(&db, sl.buf, sl.len), 0);
	keyring_free_certs(&db);

	/* Truncated lists are rejected, but may be partially loaded */
	assert_cond(efi_siglist_load_db(&db, sl.buf, sl.len - 1) < 0);
	keyring_free_certs(&db);
	assert_cond(efi_siglist_load_db(&db, sl.buf, 10) < 0);
	keyring_free_certs(&db);

	/* An empty list is fine */
	assert_inteq(efi_siglist_load_db(&db, sl.buf, 0), 0);
out:
	keyring_free_certs(&db);
	free(sl.buf);
}
bselftest(core, test_efi_db);

static void test_efi_dbx(void)
{
	struct keyring db = {
		.name = "efi-siglist-selftest",
		.links = LIST_HEAD_INIT(db.links),
		.hashes = LIST_HEAD_INIT(db.hashes),
	};
	struct keyring dbx = {
		.name = "efi-siglist-selftest-dbx",
		.links = LIST_HEAD_INIT(dbx.links),
		.hashes = LIST_HEAD_INIT(dbx.hashes),
	};
	struct keyring *bl = keyring_blacklist();
	struct x509_certificate *inter_cert = NULL;
	struct siglist sl = {}, sl_db = {};
	u8 digest[SHA256_DIGEST_SIZE], tbs[SHA256_DIGEST_SIZE + 16] = {};
	struct keyring_hash *h, *tmp;

	siglist_add(&sl_db, EFI_CERT_X509_GUID, root_der, sizeof(root_der));
	if (!assert_inteq(efi_siglist_load_db(&db, sl_db.buf, sl_db.len), 0))
		goto out;

	inter_cert = x509_cert_parse(inter_der, sizeof(inter_der));
	if (!assert_cond(!IS_ERR(inter_cert)))
		goto out;

	/* Revoke the intermediate by its TBS hash, the root by its cert */
	memcpy(tbs, inter_cert->sha256, SHA256_DIGEST_SIZE);
	siglist_add(&sl, EFI_CERT_X509_SHA256_GUID, tbs, sizeof(tbs));
	if (!assert_inteq(efi_siglist_load_dbx(&dbx, sl.buf, sl.len), 0))
		goto out;

	/* Move the loaded digests into the real blacklist */
	list_for_each_entry(h, &dbx.hashes, node)
		keyring_add_hash(bl, h->algo, h->digest, h->len);

	assert_cond(verify(sig_noattr, &db) < 0);
	assert_inteq(verify(sig_ec, &db), 0);

	list_for_each_entry(h, &dbx.hashes, node)
		keyring_del_hash(bl, h->algo, h->digest, h->len);
	assert_inteq(verify(sig_noattr, &db), 0);

	list_for_each_entry_safe(h, tmp, &dbx.hashes, node) {
		list_del(&h->node);
		free(h);
	}

	free(sl.buf);
	sl = (struct siglist) {};
	siglist_add(&sl, EFI_CERT_X509_GUID, root_der, sizeof(root_der));
	sha256(data, strlen(data), digest);
	siglist_add(&sl, EFI_CERT_SHA256_GUID, digest, sizeof(digest));
	if (!assert_inteq(efi_siglist_load_dbx(&dbx, sl.buf, sl.len), 0))
		goto out;

	/* The root's fingerprint, and the data's digest */
	assert_inteq(list_count_nodes(&dbx.hashes), 2);

	list_for_each_entry(h, &dbx.hashes, node)
		keyring_add_hash(bl, h->algo, h->digest, h->len);

	assert_cond(verify(sig_ec, &db) < 0);
	assert_cond(pkcs7_verify_buf(NULL, 0, data, strlen(data), &db, NULL) < 0);

	list_for_each_entry(h, &dbx.hashes, node)
		keyring_del_hash(bl, h->algo, h->digest, h->len);
	assert_inteq(verify(sig_ec, &db), 0);
out:
	if (!IS_ERR_OR_NULL(inter_cert))
		x509_free_certificate(inter_cert);
	keyring_free_certs(&dbx);
	keyring_free_certs(&db);
	free(sl.buf);
	free(sl_db.buf);
}
bselftest(core, test_efi_dbx);
