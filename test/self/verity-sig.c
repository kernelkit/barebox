// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <base64.h>
#include <bselftest.h>
#include <crypto/verity-sig.h>
#include <crypto/x509.h>
#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <stdio.h>
#include <string.h>
#include <xfuncs.h>

#include "pkcs7-data.h"

BSELFTEST_GLOBALS();

#define DOC_SIZE SZ_4K

struct doc_fields {
	const char *root_hash;
	const char *fingerprint;
	const char *signature;
	const char *extra;
};

/* Build a signature partition, padded with NULs, like systemd-repart does */
static char *mkdoc(const struct doc_fields *f)
{
	char *doc = xzalloc(DOC_SIZE);
	char *p = doc;

	p += sprintf(p, "{");
	if (f->root_hash)
		p += sprintf(p, "\"rootHash\":\"%s\",", f->root_hash);
	if (f->fingerprint)
		p += sprintf(p, "\"certificateFingerprint\":\"%s\",", f->fingerprint);
	if (f->extra)
		p += sprintf(p, "%s,", f->extra);
	if (f->signature)
		p += sprintf(p, "\"signature\":\"%s\"", f->signature);
	else
		p--;
	sprintf(p, "}");

	return doc;
}

static char *b64(const u8 *buf, size_t len)
{
	char *out = xzalloc(BASE64_LENGTH(len) + 1);

	uuencode(out, (const char *)buf, len);
	return out;
}

static int check(const char *doc, const struct keyring *kr, char **root_hash)
{
	char *rh = NULL;
	int ret;

	ret = verity_sig_verify(doc, DOC_SIZE, kr, &rh, NULL);
	if (root_hash)
		*root_hash = rh;
	else
		free(rh);

	return ret;
}

static void test_verity_sig(void)
{
	struct keyring root = {
		.name = "verity-selftest",
		.links = LIST_HEAD_INIT(root.links),
	};
	struct keyring rogue_kr = {
		.name = "verity-selftest-rogue",
		.links = LIST_HEAD_INIT(rogue_kr.links),
	};
	struct x509_certificate *root_cert, *rogue_cert;
	char *sig = b64(sig_root_hash, sizeof(sig_root_hash));
	char *other = b64(sig_noattr, sizeof(sig_noattr));
	char bad_hash[sizeof(root_hash)];
	struct doc_fields f;
	char *doc, *rh;

	root_cert = x509_cert_parse(root_der, sizeof(root_der));
	rogue_cert = x509_cert_parse(rogue_der, sizeof(rogue_der));
	if (!assert_cond((!IS_ERR(root_cert) && !IS_ERR(rogue_cert))))
		goto out;

	keyring_link_key(&root, root_cert->pub);
	keyring_link_key(&rogue_kr, rogue_cert->pub);

	/* Good document */
	f = (struct doc_fields) { .root_hash = root_hash, .signature = sig };
	doc = mkdoc(&f);
	if (assert_inteq(check(doc, &root, &rh), 0)) {
		assert_streq(rh, root_hash);
		free(rh);
	}
	assert_inteq(check(doc, &rogue_kr, NULL), -ENOKEY);
	free(doc);

	/* Unknown fields and a fingerprint are fine */
	f.fingerprint = "00112233445566778899aabbccddeeff";
	f.extra = "\"futureField\":[1,2,{\"a\":\"b\"}]";
	doc = mkdoc(&f);
	assert_inteq(check(doc, &root, NULL), 0);
	free(doc);
	f.fingerprint = NULL;
	f.extra = NULL;

	/* A modified root hash */
	strcpy(bad_hash, root_hash);
	bad_hash[0] = bad_hash[0] == '0' ? '1' : '0';
	f.root_hash = bad_hash;
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	/* The root hash is signed as a string, case matters */
	for (rh = bad_hash; *rh; rh++)
		*rh = toupper(root_hash[rh - bad_hash]);
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);
	f.root_hash = root_hash;

	/* A valid signature, but over something else */
	f.signature = other;
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);
	f.signature = sig;

	/* Malformed documents */
	f = (struct doc_fields) { .signature = sig };
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	f = (struct doc_fields) { .root_hash = root_hash };
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	f = (struct doc_fields) { .root_hash = "xyz", .signature = sig };
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	f = (struct doc_fields) { .root_hash = root_hash, .signature = "!!!" };
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	f = (struct doc_fields) {
		.root_hash = root_hash, .signature = sig, .fingerprint = "zz",
	};
	doc = mkdoc(&f);
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	doc = xzalloc(DOC_SIZE);
	assert_cond(check(doc, &root, NULL) < 0);
	strcpy(doc, "[\"rootHash\"]");
	assert_cond(check(doc, &root, NULL) < 0);
	strcpy(doc, "{\"rootHash\":");
	assert_cond(check(doc, &root, NULL) < 0);
	free(doc);

	/* Not NUL terminated within the buffer */
	f = (struct doc_fields) { .root_hash = root_hash, .signature = sig };
	doc = mkdoc(&f);
	memset(doc + strlen(doc), ' ', DOC_SIZE - strlen(doc));
	assert_inteq(check(doc, &root, NULL), 0);
	free(doc);

	keyring_unlink_key(&root, root_cert->pub);
	keyring_unlink_key(&rogue_kr, rogue_cert->pub);
out:
	if (!IS_ERR(root_cert))
		x509_free_certificate(root_cert);
	if (!IS_ERR(rogue_cert))
		x509_free_certificate(rogue_cert);
	free(other);
	free(sig);
}
bselftest(core, test_verity_sig);
