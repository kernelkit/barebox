// SPDX-License-Identifier: GPL-2.0-or-later
/* Instantiate a public key crypto key from an X.509 Certificate
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "X.509: "fmt
#include <common.h>
#include <digest.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/asn1_decoder.h>
#include <crypto/rsa.h>
#include <crypto/ecdsa.h>
#include "x509_parser.h"
#include "rsapubkey.asn1.h"

static int x509_sha256(const void *data, size_t len, u8 *out)
{
	struct digest *d;
	int ret;

	d = digest_alloc_by_algo(HASH_ALGO_SHA256);
	if (!d)
		return -ENOPKG;

	ret = digest_digest(d, data, len, out);
	digest_free(d);
	return ret;
}

/*
 * Set up the signature parameters in an X.509 certificate.  This involves
 * digesting the signed data and extracting the signature.
 */
int x509_get_sig_params(struct x509_certificate *cert)
{
	struct public_key_signature *sig = cert->sig;
	struct digest *d;
	int ret;

	pr_devel("==>%s()\n", __func__);

	/* Calculate a SHA256 hash of the TBS and check it against the
	 * blacklist.
	 */
	ret = x509_sha256(cert->tbs, cert->tbs_size, cert->sha256);
	if (ret < 0)
		return ret;

	ret = x509_sha256(cert->raw, cert->raw_size, cert->fingerprint);
	if (ret < 0)
		return ret;

	if (blacklist_has_hash(HASH_ALGO_SHA256, cert->sha256, sizeof(cert->sha256)) ||
	    blacklist_has_hash(HASH_ALGO_SHA256, cert->fingerprint,
			       sizeof(cert->fingerprint))) {
		pr_err("Cert %*phN is blacklisted\n",
		       (int)sizeof(cert->sha256), cert->sha256);
		cert->blacklisted = true;
	}

	sig->s = kmemdup(cert->raw_sig, cert->raw_sig_size, GFP_KERNEL);
	if (!sig->s)
		return -ENOMEM;

	sig->s_size = cert->raw_sig_size;

	if (cert->unsupported_sig)
		return 0;

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	d = digest_alloc(sig->hash_algo);
	if (!d) {
		cert->unsupported_sig = true;
		return 0;
	}

	sig->m_size = digest_length(d);

	ret = -ENOMEM;
	sig->m = kmalloc(sig->m_size, GFP_KERNEL);
	if (!sig->m)
		goto error;
	sig->m_free = true;

	ret = digest_digest(d, cert->tbs, cert->tbs_size, sig->m);

error:
	digest_free(d);
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}

/*
 * Check for self-signedness in an X.509 cert and if found, check the signature
 * immediately if we can.
 */
int x509_check_for_self_signed(struct x509_certificate *cert)
{
	int ret = 0;

	pr_devel("==>%s()\n", __func__);

	if (cert->raw_subject_size != cert->raw_issuer_size ||
	    memcmp(cert->raw_subject, cert->raw_issuer,
		   cert->raw_issuer_size) != 0)
		goto not_self_signed;

	if (cert->sig->auth_ids[0] || cert->sig->auth_ids[1]) {
		/* If the AKID is present it may have one or two parts.  If
		 * both are supplied, both must match.
		 */
		bool a = asymmetric_key_id_same(cert->skid, cert->sig->auth_ids[1]);
		bool b = asymmetric_key_id_same(cert->id, cert->sig->auth_ids[0]);

		if (!a && !b)
			goto not_self_signed;

		ret = -EKEYREJECTED;
		if (((a && !b) || (b && !a)) &&
		    cert->sig->auth_ids[0] && cert->sig->auth_ids[1])
			goto out;
	}

	if (cert->unsupported_sig) {
		ret = 0;
		goto out;
	}

	ret = public_key_verify_signature(cert->pub, cert->sig);
	if (ret < 0) {
		if (ret == -ENOPKG) {
			cert->unsupported_sig = true;
			ret = 0;
		}
		goto out;
	}

	pr_devel("Cert Self-signature verified");
	cert->self_signed = true;

out:
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;

not_self_signed:
	pr_devel("<==%s() = 0 [not]\n", __func__);
	return 0;
}

/*
 * Fill in the key's fingerprint, which, just like keytoc does for
 * compiled in keys, is the SHA256 of the SubjectPublicKeyInfo.
 */
int x509_public_key_hash(struct x509_certificate *cert)
{
	struct public_key *pub = cert->pub;
	u8 *hash;
	int ret;

	hash = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	ret = x509_sha256(cert->raw_spki, cert->raw_spki_size, hash);
	if (ret < 0) {
		kfree(hash);
		return ret;
	}

	pub->hash = hash;
	pub->hashlen = SHA256_DIGEST_SIZE;
	return 0;
}

struct x509_rsa_ctx {
	const u8 *n, *e;
	size_t n_len, e_len;
};

int x509_rsa_note_n(void *context, size_t hdrlen, unsigned char tag,
		    const void *value, size_t vlen)
{
	struct x509_rsa_ctx *ctx = context;

	ctx->n = value;
	ctx->n_len = vlen;
	return 0;
}

int x509_rsa_note_e(void *context, size_t hdrlen, unsigned char tag,
		    const void *value, size_t vlen)
{
	struct x509_rsa_ctx *ctx = context;

	ctx->e = value;
	ctx->e_len = vlen;
	return 0;
}

static struct public_key *x509_rsa_key_create(const void *key, size_t keylen)
{
	struct x509_rsa_ctx ctx = {};
	struct rsa_public_key *rsa;
	struct public_key *pub;
	u64 e = 0;
	int ret;

	if (!IS_ENABLED(CONFIG_CRYPTO_RSA))
		return ERR_PTR(-ENOPKG);

	ret = asn1_ber_decoder(&rsapubkey_decoder, &ctx, key, keylen);
	if (ret < 0)
		return ERR_PTR(ret);

	while (ctx.e_len && !*ctx.e) {
		ctx.e++;
		ctx.e_len--;
	}

	if (ctx.e_len > sizeof(e))
		return ERR_PTR(-EOPNOTSUPP);

	while (ctx.e_len--)
		e = (e << 8) | *ctx.e++;

	rsa = rsa_key_create(ctx.n, ctx.n_len, e);
	if (IS_ERR(rsa))
		return ERR_CAST(rsa);

	pub = kzalloc(sizeof(*pub), GFP_KERNEL);
	if (!pub) {
		rsa_key_free(rsa);
		return ERR_PTR(-ENOMEM);
	}

	pub->type = PUBLIC_KEY_TYPE_RSA;
	pub->rsa = rsa;
	return pub;
}

static void x509_ecdsa_coord(u64 *digits, const u8 *be, unsigned int ndigits)
{
	unsigned int i;

	__be64 digit;

	for (i = 0; i < ndigits; i++) {
		memcpy(&digit, be + (ndigits - 1 - i) * 8, sizeof(digit));
		digits[i] = be64_to_cpu(digit);
	}
}

static struct public_key *x509_ecdsa_key_create(const void *params,
						size_t paramlen,
						const u8 *key, size_t keylen)
{
	struct ecdsa_public_key *ecdsa;
	struct public_key *pub;
	const char *curve_name;
	unsigned int bytes;
	u64 *x, *y;
	enum OID oid;

	if (!IS_ENABLED(CONFIG_CRYPTO_ECDSA))
		return ERR_PTR(-ENOPKG);

	if (parse_OID(params, paramlen, &oid) != 0)
		return ERR_PTR(-EBADMSG);

	switch (oid) {
	case OID_id_prime256v1:
		curve_name = "prime256v1";
		break;
	case OID_id_ansip384r1:
		curve_name = "secp384r1";
		break;
	default:
		return ERR_PTR(-ENOPKG);
	}

	bytes = ecdsa_key_size(curve_name) / 8;
	if (!bytes)
		return ERR_PTR(-ENOPKG);

	/* Only uncompressed points are supported */
	if (keylen != 1 + 2 * bytes || key[0] != 0x04)
		return ERR_PTR(-EBADMSG);

	pub = kzalloc(sizeof(*pub), GFP_KERNEL);
	ecdsa = kzalloc(sizeof(*ecdsa), GFP_KERNEL);
	x = kzalloc(bytes, GFP_KERNEL);
	y = kzalloc(bytes, GFP_KERNEL);
	if (!pub || !ecdsa || !x || !y) {
		kfree(pub);
		kfree(ecdsa);
		kfree(x);
		kfree(y);
		return ERR_PTR(-ENOMEM);
	}

	x509_ecdsa_coord(x, key + 1, bytes / 8);
	x509_ecdsa_coord(y, key + 1 + bytes, bytes / 8);

	ecdsa->curve_name = curve_name;
	ecdsa->x = x;
	ecdsa->y = y;

	pub->type = PUBLIC_KEY_TYPE_ECDSA;
	pub->ecdsa = ecdsa;
	return pub;
}

/*
 * Convert the SubjectPublicKeyInfo of a certificate to a key in the
 * format expected by the RSA/ECDSA implementations.
 */
struct public_key *x509_public_key_create(enum OID algo,
					  const void *params, size_t paramlen,
					  const void *key, size_t keylen)
{
	switch (algo) {
	case OID_rsaEncryption:
		return x509_rsa_key_create(key, keylen);
	case OID_id_ecPublicKey:
		return x509_ecdsa_key_create(params, paramlen, key, keylen);
	default:
		return ERR_PTR(-ENOPKG);
	}
}

void public_key_free(struct public_key *key)
{
	if (!key)
		return;

	switch (key->type) {
	case PUBLIC_KEY_TYPE_RSA:
		rsa_key_free((struct rsa_public_key *)key->rsa);
		break;
	case PUBLIC_KEY_TYPE_ECDSA:
		if (key->ecdsa) {
			kfree(key->ecdsa->x);
			kfree(key->ecdsa->y);
			kfree(key->ecdsa);
		}
		break;
	}

	kfree(key->hash);
	kfree(key->key_name_hint);
	kfree(key);
}
