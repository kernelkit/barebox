// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <bselftest.h>
#include <crypto/pkcs7.h>
#include <crypto/x509.h>
#include <libfile.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <xfuncs.h>

#include "pkcs7-data.h"

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
