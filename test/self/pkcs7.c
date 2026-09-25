// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <bselftest.h>
#include <digest.h>
#include <crypto/sha.h>
#include <crypto/ecdsa.h>
#include <crypto/pkcs7.h>
#include <crypto/public_key.h>
#include <crypto/rsa.h>
#include <crypto/x509.h>
#include <libfile.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <xfuncs.h>

#include "pkcs7-data.h"

/* The root certificate, compiled in by keytoc */
#include "pkcs7-root.pem.h"

BSELFTEST_GLOBALS();

#define TKR_MAX_CERTS 4

struct test_keyring {
	struct keyring kr;
	struct x509_certificate *certs[TKR_MAX_CERTS];
	int n;
};

static void tkr_init(struct test_keyring *tkr)
{
	memset(tkr, 0, sizeof(*tkr));
	tkr->kr.name = "pkcs7-selftest";
	INIT_LIST_HEAD(&tkr->kr.links);
	INIT_LIST_HEAD(&tkr->kr.node);
}

static const struct public_key *__tkr_add(struct test_keyring *tkr,
					  const u8 *der, size_t len)
{
	struct x509_certificate *cert;

	if (WARN_ON(tkr->n == TKR_MAX_CERTS))
		return NULL;

	cert = x509_cert_parse(der, len);
	if (!assert_cond(!IS_ERR(cert)))
		return NULL;

	tkr->certs[tkr->n++] = cert;
	keyring_link_key(&tkr->kr, cert->pub);
	return cert->pub;
}

#define tkr_add(_tkr, _name) __tkr_add(_tkr, _name##_der, sizeof(_name##_der))

static void tkr_free(struct test_keyring *tkr)
{
	int i;

	for (i = 0; i < tkr->n; i++) {
		keyring_unlink_key(&tkr->kr, tkr->certs[i]->pub);
		x509_free_certificate(tkr->certs[i]);
	}
}

#define verify(_sig, _tkr, _key)				\
	pkcs7_verify_buf(_sig, sizeof(_sig), data, strlen(data),	\
			 &(_tkr)->kr, _key)

/* Trust anchors at every level of the chain */
static void test_pkcs7_chain(void)
{
	const struct public_key *anchor, *key;
	struct test_keyring tkr;

	tkr_init(&tkr);
	anchor = tkr_add(&tkr, root);
	if (anchor) {
		key = NULL;
		assert_inteq(verify(sig_noattr, &tkr, &key), 0);
		assert_cond(key == anchor);

		key = NULL;
		assert_inteq(verify(sig_attrs, &tkr, &key), 0);
		assert_cond(key == anchor);

		key = NULL;
		assert_inteq(verify(sig_keyid, &tkr, &key), 0);
		assert_cond(key == anchor);

		/* ECDSA leaf directly under the root */
		assert_inteq(verify(sig_ec, &tkr, NULL), 0);

		/* Leaf without AKID, found by its issuer's name */
		key = NULL;
		assert_inteq(verify(sig_noakid, &tkr, &key), 0);
		assert_cond(key == anchor);

		/* One of the signers is trusted */
		assert_inteq(verify(sig_multi, &tkr, NULL), 0);
	}
	tkr_free(&tkr);

	tkr_init(&tkr);
	anchor = tkr_add(&tkr, inter);
	if (anchor) {
		key = NULL;
		assert_inteq(verify(sig_noattr, &tkr, &key), 0);
		assert_cond(key == anchor);

		/* Not issued by the intermediate */
		assert_inteq(verify(sig_ec, &tkr, NULL), -ENOKEY);
	}
	tkr_free(&tkr);

	tkr_init(&tkr);
	anchor = tkr_add(&tkr, leaf);
	if (anchor) {
		key = NULL;
		assert_inteq(verify(sig_noattr, &tkr, &key), 0);
		assert_cond(key == anchor);

		key = NULL;
		assert_inteq(verify(sig_keyid, &tkr, &key), 0);
		assert_cond(key == anchor);
	}
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_chain);

/* Messages without certificates can only be verified by their signer */
static void test_pkcs7_nocerts(void)
{
	const struct public_key *anchor, *key = NULL;
	struct test_keyring tkr;

	tkr_init(&tkr);
	if (tkr_add(&tkr, root) && tkr_add(&tkr, inter))
		assert_inteq(verify(sig_nocerts, &tkr, NULL), -ENOKEY);
	tkr_free(&tkr);

	tkr_init(&tkr);
	anchor = tkr_add(&tkr, leaf);
	if (anchor) {
		assert_inteq(verify(sig_nocerts, &tkr, &key), 0);
		assert_cond(key == anchor);
	}
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_nocerts);

static void test_pkcs7_untrusted(void)
{
	struct test_keyring tkr;

	/* Nothing in the keyring */
	tkr_init(&tkr);
	assert_inteq(verify(sig_noattr, &tkr, NULL), -ENOKEY);
	tkr_free(&tkr);

	tkr_init(&tkr);
	if (tkr_add(&tkr, root)) {
		assert_inteq(verify(sig_rogue, &tkr, NULL), -ENOKEY);

		/* Embedded data can't be combined with detached data */
		assert_cond(verify(sig_attached, &tkr, NULL) < 0);
	}
	tkr_free(&tkr);

	/* Self-signed, but explicitly trusted */
	tkr_init(&tkr);
	if (tkr_add(&tkr, rogue)) {
		assert_inteq(verify(sig_rogue, &tkr, NULL), 0);
		assert_inteq(verify(sig_multi, &tkr, NULL), 0);
		assert_inteq(verify(sig_noattr, &tkr, NULL), -ENOKEY);
	}
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_untrusted);

static void test_pkcs7_bad_data(void)
{
	static const u8 * const sigs[] = {
		sig_noattr, sig_attrs, sig_nocerts, sig_keyid, sig_ec,
	};
	static const size_t sizes[] = {
		sizeof(sig_noattr), sizeof(sig_attrs), sizeof(sig_nocerts),
		sizeof(sig_keyid), sizeof(sig_ec),
	};
	struct test_keyring tkr;
	size_t len = strlen(data);
	char *bad;
	int i, ret;

	tkr_init(&tkr);
	if (!tkr_add(&tkr, root) || !tkr_add(&tkr, leaf))
		goto out;

	bad = xstrdup(data);
	bad[0] ^= 1;

	for (i = 0; i < ARRAY_SIZE(sigs); i++) {
		/* Sanity check */
		assert_inteq(pkcs7_verify_buf(sigs[i], sizes[i], data, len,
					      &tkr.kr, NULL), 0);

		ret = pkcs7_verify_buf(sigs[i], sizes[i], bad, len,
				       &tkr.kr, NULL);
		if (!assert_cond((ret < 0 && ret != -ENOKEY)))
			pr_err("sig %d: modified data: %pe\n", i, ERR_PTR(ret));

		ret = pkcs7_verify_buf(sigs[i], sizes[i], data, len - 1,
				       &tkr.kr, NULL);
		if (!assert_cond((ret < 0 && ret != -ENOKEY)))
			pr_err("sig %d: truncated data: %pe\n", i, ERR_PTR(ret));
	}

	free(bad);
out:
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_bad_data);

/* Large files are digested piecewise */
static void test_pkcs7_file(void)
{
	static const char *path = "/pkcs7-selftest-data";
	struct test_keyring tkr;
	char *bad;

	tkr_init(&tkr);
	if (!tkr_add(&tkr, root))
		goto out;

	if (!assert_inteq(write_file(path, data, strlen(data)), 0))
		goto out;

	assert_inteq(pkcs7_verify_file(sig_noattr, sizeof(sig_noattr), path,
				       &tkr.kr, NULL), 0);
	assert_inteq(pkcs7_verify_file(sig_attrs, sizeof(sig_attrs), path,
				       &tkr.kr, NULL), 0);
	/* SHA-384 */
	assert_inteq(pkcs7_verify_file(sig_ec, sizeof(sig_ec), path,
				       &tkr.kr, NULL), 0);
	assert_inteq(pkcs7_verify_file(sig_rogue, sizeof(sig_rogue), path,
				       &tkr.kr, NULL), -ENOKEY);

	bad = xstrdup(data);
	bad[3] ^= 0x40;
	if (assert_inteq(write_file(path, bad, strlen(bad)), 0)) {
		assert_cond(pkcs7_verify_file(sig_noattr, sizeof(sig_noattr),
					      path, &tkr.kr, NULL) < 0);
		assert_cond(pkcs7_verify_file(sig_attrs, sizeof(sig_attrs),
					      path, &tkr.kr, NULL) < 0);
	}
	free(bad);

	assert_cond(pkcs7_verify_file(sig_noattr, sizeof(sig_noattr),
				      "/does/not/exist", &tkr.kr, NULL) < 0);

	unlink(path);
out:
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_file);

static void test_pkcs7_corrupt(void)
{
	struct test_keyring tkr;
	size_t i, sig_start;
	u8 *buf;
	int ret;

	tkr_init(&tkr);
	if (!tkr_add(&tkr, root))
		goto out;

	buf = xmemdup(sig_attrs, sizeof(sig_attrs));

	/* Every truncation must be rejected */
	for (i = 0; i < sizeof(sig_attrs); i++) {
		ret = pkcs7_verify_buf(buf, i, data, strlen(data), &tkr.kr, NULL);
		if (!assert_cond(ret < 0)) {
			pr_err("truncation to %zu bytes accepted\n", i);
			break;
		}
	}

	/*
	 * Flip a sample of the bits, one at a time, to shake out any
	 * parser bugs. Not all of the message is covered by a signature
	 * (e.g. the digestAlgorithms set), so we can't expect all of them
	 * to be rejected. The fuzzer covers this more thoroughly.
	 */
	for (i = 0; i < 8 * sizeof(sig_attrs); i += 13) {
		struct pkcs7_message *pkcs7;

		buf[i / 8] ^= BIT(i % 8);
		pkcs7 = pkcs7_parse_message(buf, sizeof(sig_attrs));
		if (!IS_ERR(pkcs7))
			pkcs7_free_message(pkcs7);
		buf[i / 8] ^= BIT(i % 8);
	}
	free(buf);

	/* ...but flipping any bit of the RSA signature is fatal. */
	buf = xmemdup(sig_noattr, sizeof(sig_noattr));
	sig_start = sizeof(sig_noattr) - 2048 / 8;
	for (i = 8 * sig_start; i < 8 * sizeof(sig_noattr); i += 61) {
		buf[i / 8] ^= BIT(i % 8);
		ret = pkcs7_verify_buf(buf, sizeof(sig_noattr), data,
				       strlen(data), &tkr.kr, NULL);
		if (!assert_cond((ret < 0 && ret != -ENOKEY)))
			pr_err("bit %zu flipped: %pe\n", i, ERR_PTR(ret));
		buf[i / 8] ^= BIT(i % 8);
	}
	free(buf);
out:
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_corrupt);

/* Compiled in keys are usable as trust anchors */
static void test_pkcs7_builtin(void)
{
	const struct public_key *key, *found = NULL;
	const struct keyring *kr;

	kr = keyring_find("selftest-pkcs7");
	if (!assert_cond(kr))
		return;

	key = keyring_find_key(kr, "pkcs7-root");
	if (!assert_cond(!IS_ERR(key)))
		return;

	/* The key's certificate is parsed during initialization */
	if (!assert_cond(key->cert))
		return;

	assert_streq(key->cert->subject, "barebox: root");
	assert_cond(key->cert->pub == key);

	/*
	 * The parameters derived at runtime must match the ones keytoc
	 * computed for the same key using OpenSSL.
	 */
	if (assert_cond((key->type == PUBLIC_KEY_TYPE_RSA &&
			 key->rsa->len == key_1.len))) {
		assert_cond(key->rsa->n0inv == key_1.n0inv);
		assert_cond(key->rsa->exponent == key_1.exponent);
		assert_cond(!memcmp(key->rsa->modulus, key_1.modulus,
				    key_1.len * sizeof(uint32_t)));
		assert_cond(!memcmp(key->rsa->rr, key_1.rr,
				    key_1.len * sizeof(uint32_t)));
	}
	assert_cond(!memcmp(key->hash, key_1_hash, sizeof(key_1_hash)));

	assert_inteq(pkcs7_verify_buf(sig_noattr, sizeof(sig_noattr),
				      data, strlen(data), kr, &found), 0);
	assert_cond(found == key);

	assert_inteq(pkcs7_verify_buf(sig_rogue, sizeof(sig_rogue),
				      data, strlen(data), kr, NULL), -ENOKEY);
}
bselftest(core, test_pkcs7_builtin);

static void data_sha256(u8 *digest)
{
	struct digest *d = digest_alloc_by_algo(HASH_ALGO_SHA256);

	digest_digest(d, data, strlen(data), digest);
	digest_free(d);
}

/* Revoked certificates and data are rejected, whatever the signature */
static void test_pkcs7_blacklist(void)
{
	struct keyring *bl = keyring_blacklist();
	struct x509_certificate *inter_cert;
	u8 digest[SHA256_DIGEST_SIZE];
	struct test_keyring tkr;
	const struct public_key *root_key;

	if (!assert_cond(bl))
		return;

	tkr_init(&tkr);
	root_key = tkr_add(&tkr, root);
	inter_cert = x509_cert_parse(inter_der, sizeof(inter_der));
	if (!root_key || !assert_cond(!IS_ERR(inter_cert)))
		goto out;

	/* The trust anchor itself, by the hash of the whole certificate */
	keyring_add_hash(bl, HASH_ALGO_SHA256, root_key->cert->fingerprint,
			 SHA256_DIGEST_SIZE);
	assert_inteq(verify(sig_noattr, &tkr, NULL), -ENOKEY);
	keyring_del_hash(bl, HASH_ALGO_SHA256, root_key->cert->fingerprint,
			 SHA256_DIGEST_SIZE);
	assert_inteq(verify(sig_noattr, &tkr, NULL), 0);

	/* An intermediate in the message, by the hash of its TBS */
	keyring_add_hash(bl, HASH_ALGO_SHA256, inter_cert->sha256,
			 SHA256_DIGEST_SIZE);
	assert_cond(verify(sig_noattr, &tkr, NULL) < 0);
	assert_cond(verify(sig_attrs, &tkr, NULL) < 0);
	/* ...but a chain that does not involve it is fine */
	assert_inteq(verify(sig_ec, &tkr, NULL), 0);
	keyring_del_hash(bl, HASH_ALGO_SHA256, inter_cert->sha256,
			 SHA256_DIGEST_SIZE);

	/* The data itself, even when signed with another digest */
	data_sha256(digest);
	keyring_add_hash(bl, HASH_ALGO_SHA256, digest, sizeof(digest));
	assert_inteq(verify(sig_noattr, &tkr, NULL), -EKEYREJECTED);
	assert_inteq(verify(sig_ec, &tkr, NULL), -EKEYREJECTED);
	keyring_del_hash(bl, HASH_ALGO_SHA256, digest, sizeof(digest));

	assert_inteq(verify(sig_noattr, &tkr, NULL), 0);
out:
	if (!IS_ERR_OR_NULL(inter_cert))
		x509_free_certificate(inter_cert);
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_blacklist);

/* Keyrings can vouch for data by its digest alone */
static void test_pkcs7_allowlist(void)
{
	static const char *path = "/pkcs7-selftest-allow";
	const struct public_key *key = (void *)1;
	struct keyring *bl = keyring_blacklist();
	u8 digest[SHA256_DIGEST_SIZE];
	struct test_keyring tkr;

	tkr_init(&tkr);
	data_sha256(digest);

	assert_inteq(pkcs7_verify_buf(NULL, 0, data, strlen(data),
				      &tkr.kr, NULL), -ENOKEY);

	keyring_add_hash(&tkr.kr, HASH_ALGO_SHA256, digest, sizeof(digest));

	assert_inteq(pkcs7_verify_buf(NULL, 0, data, strlen(data),
				      &tkr.kr, &key), 0);
	assert_cond(!key);

	/* An untrusted signature doesn't matter */
	assert_inteq(verify(sig_rogue, &tkr, NULL), 0);
	/* Other data does */
	assert_inteq(pkcs7_verify_buf(NULL, 0, data, strlen(data) - 1,
				      &tkr.kr, NULL), -ENOKEY);

	if (assert_inteq(write_file(path, data, strlen(data)), 0)) {
		assert_inteq(pkcs7_verify_file(NULL, 0, path, &tkr.kr, NULL), 0);
		assert_inteq(pkcs7_verify_file(sig_rogue, sizeof(sig_rogue),
					       path, &tkr.kr, NULL), 0);
		/* SHA-384 signature, so the SHA256 is computed separately */
		assert_inteq(pkcs7_verify_file(sig_ec, sizeof(sig_ec),
					       path, &tkr.kr, NULL), 0);

		/* The blacklist trumps everything */
		keyring_add_hash(bl, HASH_ALGO_SHA256, digest, sizeof(digest));
		assert_inteq(pkcs7_verify_file(NULL, 0, path, &tkr.kr, NULL),
			     -EKEYREJECTED);
		keyring_del_hash(bl, HASH_ALGO_SHA256, digest, sizeof(digest));

		unlink(path);
	}

	/* Hashes are found in sub-keyrings as well */
	{
		struct keyring *outer = keyring_find("pkcs7-selftest-outer");

		if (!outer)
			outer = keyring_create("pkcs7-selftest-outer");

		if (assert_cond(!IS_ERR(outer))) {
			keyring_link_keyring(outer, &tkr.kr);
			assert_inteq(pkcs7_verify_buf(NULL, 0, data, strlen(data),
						      outer, NULL), 0);
			keyring_unlink_keyring(outer, &tkr.kr);
		}
	}

	keyring_del_hash(&tkr.kr, HASH_ALGO_SHA256, digest, sizeof(digest));
	tkr_free(&tkr);
}
bselftest(core, test_pkcs7_allowlist);
