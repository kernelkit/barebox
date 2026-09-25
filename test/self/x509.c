// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <bselftest.h>
#include <crypto/ecdsa.h>
#include <crypto/rsa.h>
#include <crypto/x509.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <string.h>
#include <xfuncs.h>

#include "x509-certs.h"

BSELFTEST_GLOBALS();

static bool hash_eq(const u8 *hash, unsigned int len, const char *hex)
{
	char buf[2 * SHA256_DIGEST_SIZE + 1];

	if (len != SHA256_DIGEST_SIZE)
		return false;

	snprintf(buf, sizeof(buf), "%*phN", len, hash);
	return !strcmp(buf, hex);
}

#define parse_cert(_name) x509_cert_parse(_name##_der, sizeof(_name##_der))

#define check_ids(_cert, _name) ({					\
	assert_cond(hash_eq((_cert)->pub->hash, (_cert)->pub->hashlen,	\
			    _name##_spki_sha256));			\
	assert_cond(hash_eq((_cert)->fingerprint,			\
			    sizeof((_cert)->fingerprint),		\
			    _name##_fingerprint));			\
})

static void test_x509_rsa(void)
{
	struct x509_certificate *ca, *leaf, *root;

	ca = parse_cert(ca_rsa);
	if (!assert_cond(!IS_ERR(ca)))
		return;

	assert_streq(ca->subject, "barebox: ca_rsa");
	assert_streq(ca->issuer, "barebox: ca_rsa");
	assert_cond(ca->self_signed);
	assert_cond(!ca->unsupported_sig);
	assert_cond(ca->pub->type == PUBLIC_KEY_TYPE_RSA);
	assert_cond(ca->pub->rsa->len == 2048 / 32);
	assert_cond(ca->pub->cert == ca);
	assert_cond(ca->skid);
	assert_cond(test_bit(KEY_EFLAG_CA, &ca->key_eflags));
	check_ids(ca, ca_rsa);

	leaf = parse_cert(leaf_rsa);
	if (assert_cond(!IS_ERR(leaf))) {
		assert_streq(leaf->subject, "barebox: leaf_rsa");
		assert_streq(leaf->issuer, "barebox: ca_rsa");
		assert_cond(!leaf->self_signed);
		assert_cond(leaf->pub->rsa->len == 3072 / 32);
		assert_cond(!test_bit(KEY_EFLAG_CA, &leaf->key_eflags));
		assert_cond(test_bit(KEY_EFLAG_DIGITALSIG, &leaf->key_eflags));
		check_ids(leaf, leaf_rsa);

		/* The AKID must point back to the CA */
		assert_cond(asymmetric_key_id_same(leaf->sig->auth_ids[1],
						   ca->skid));

		/* SHA-384 signature by the CA */
		assert_inteq(public_key_verify_signature(ca->pub, leaf->sig), 0);

		/* The leaf didn't sign itself */
		assert_cond(public_key_verify_signature(leaf->pub, leaf->sig) < 0);

		x509_free_certificate(leaf);
	}

	/* 4096-bit keys, SHA-512 */
	root = parse_cert(root_rsa4096);
	if (assert_cond(!IS_ERR(root))) {
		assert_cond(root->self_signed);
		assert_cond(root->pub->rsa->len == 4096 / 32);
		check_ids(root, root_rsa4096);

		assert_cond(public_key_verify_signature(root->pub, ca->sig) < 0);
		x509_free_certificate(root);
	}

	x509_free_certificate(ca);
}
bselftest(core, test_x509_rsa);

static void test_x509_ecdsa(void)
{
	struct x509_certificate *ca, *leaf, *rsa;

	ca = parse_cert(ca_ec);
	if (!assert_cond(!IS_ERR(ca)))
		return;

	assert_cond(ca->self_signed);
	assert_cond(ca->pub->type == PUBLIC_KEY_TYPE_ECDSA);
	assert_streq(ca->pub->ecdsa->curve_name, "prime256v1");
	check_ids(ca, ca_ec);

	leaf = parse_cert(leaf_ec);
	if (assert_cond(!IS_ERR(leaf))) {
		assert_cond(!leaf->self_signed);
		check_ids(leaf, leaf_ec);
		assert_inteq(public_key_verify_signature(ca->pub, leaf->sig), 0);
		assert_cond(public_key_verify_signature(leaf->pub, leaf->sig) < 0);
		x509_free_certificate(leaf);
	}

	/* P-384 key, certified by an RSA CA */
	rsa = parse_cert(ca_rsa);
	leaf = parse_cert(leaf_ec384);
	if (assert_cond((!IS_ERR(rsa) && !IS_ERR(leaf)))) {
		assert_cond(leaf->pub->type == PUBLIC_KEY_TYPE_ECDSA);
		assert_streq(leaf->pub->ecdsa->curve_name, "secp384r1");
		check_ids(leaf, leaf_ec384);
		assert_inteq(public_key_verify_signature(rsa->pub, leaf->sig), 0);

		/* Wrong key type altogether */
		assert_cond(public_key_verify_signature(ca->pub, leaf->sig) < 0);
	}

	if (!IS_ERR(leaf))
		x509_free_certificate(leaf);
	if (!IS_ERR(rsa))
		x509_free_certificate(rsa);
	x509_free_certificate(ca);
}
bselftest(core, test_x509_ecdsa);

static void test_x509_unsupported(void)
{
	struct x509_certificate *cert, *ca;

	/*
	 * An RSA-PSS signature can't be verified, but the key itself
	 * is perfectly usable.
	 */
	cert = parse_cert(leaf_pss);
	if (assert_cond(!IS_ERR(cert))) {
		assert_cond(cert->unsupported_sig);
		assert_cond(cert->pub->type == PUBLIC_KEY_TYPE_RSA);
		check_ids(cert, leaf_pss);

		ca = parse_cert(ca_rsa);
		if (assert_cond(!IS_ERR(ca))) {
			assert_inteq(public_key_verify_signature(ca->pub, cert->sig),
				     -ENOPKG);
			x509_free_certificate(ca);
		}
		x509_free_certificate(cert);
	}

	/* Ed25519 keys, on the other hand, are not */
	cert = parse_cert(ed25519);
	assert_cond((IS_ERR(cert) && PTR_ERR(cert) == -ENOPKG));
}
bselftest(core, test_x509_unsupported);

static void test_x509_ids(void)
{
	struct x509_certificate *a, *b;

	a = parse_cert(ca_rsa);
	b = parse_cert(ca_rsa_reissued);
	if (!assert_cond((!IS_ERR(a) && !IS_ERR(b))))
		goto out;

	/* Same key, same subject, different serial */
	assert_cond(hash_eq(b->pub->hash, b->pub->hashlen,
			    ca_rsa_spki_sha256));
	assert_cond(asymmetric_key_id_same(a->skid, b->skid));
	assert_cond(!asymmetric_key_id_same(a->id, b->id));
	assert_cond(memcmp(a->fingerprint, b->fingerprint,
			   sizeof(a->fingerprint)));

	/* Either can verify the other, since the key is the same */
	assert_inteq(public_key_verify_signature(a->pub, b->sig), 0);
	assert_inteq(public_key_verify_signature(b->pub, a->sig), 0);
out:
	if (!IS_ERR(a))
		x509_free_certificate(a);
	if (!IS_ERR(b))
		x509_free_certificate(b);
}
bselftest(core, test_x509_ids);

static void test_x509_corrupt(void)
{
	struct x509_certificate *ca, *orig, *cert;
	size_t i, tbs_start, tbs_end;
	u8 *buf;

	ca = parse_cert(ca_rsa);
	orig = parse_cert(leaf_rsa);
	if (!assert_cond((!IS_ERR(ca) && !IS_ERR(orig))))
		goto out;

	tbs_start = orig->tbs - orig->raw;
	tbs_end = tbs_start + orig->tbs_size;

	buf = xmemdup(leaf_rsa_der, sizeof(leaf_rsa_der));

	/* Every truncation must be rejected */
	for (i = 0; i < sizeof(leaf_rsa_der); i++) {
		cert = x509_cert_parse(buf, i);
		if (!assert_cond(IS_ERR(cert))) {
			pr_err("truncation to %zu bytes accepted\n", i);
			x509_free_certificate(cert);
			break;
		}
	}

	/* A flipped bit in the signature invalidates it */
	buf[sizeof(leaf_rsa_der) - 8] ^= 0x10;
	cert = x509_cert_parse(buf, sizeof(leaf_rsa_der));
	if (assert_cond(!IS_ERR(cert))) {
		assert_cond(public_key_verify_signature(ca->pub, cert->sig) < 0);
		x509_free_certificate(cert);
	}
	buf[sizeof(leaf_rsa_der) - 8] ^= 0x10;

	/*
	 * Flip a sample of the bits of the TBS (every 17th, to cover all
	 * bit positions while keeping the runtime down on slow targets),
	 * one at a time; either the parser rejects the result, or the
	 * signature no longer matches.
	 */
	for (i = 8 * tbs_start; i < 8 * tbs_end; i += 17) {
		buf[i / 8] ^= BIT(i % 8);

		cert = x509_cert_parse(buf, sizeof(leaf_rsa_der));
		if (!IS_ERR(cert)) {
			if (!assert_cond(public_key_verify_signature(ca->pub,
								     cert->sig)))
				pr_err("bit %zu flipped, still valid\n", i);
			x509_free_certificate(cert);
		}

		buf[i / 8] ^= BIT(i % 8);
	}

	free(buf);
out:
	if (!IS_ERR(orig))
		x509_free_certificate(orig);
	if (!IS_ERR(ca))
		x509_free_certificate(ca);
}
bselftest(core, test_x509_corrupt);
