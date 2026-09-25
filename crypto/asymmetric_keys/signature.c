// SPDX-License-Identifier: GPL-2.0-or-later
/* Signature verification with an asymmetric key
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "SIG: "fmt
#include <common.h>
#include <digest.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/overflow.h>
#include <linux/limits.h>
#include <linux/asn1_decoder.h>
#include <crypto/rsa.h>
#include <crypto/ecdsa.h>
#include <crypto/x509.h>
#include "ecdsasignature.asn1.h"

/**
 * asymmetric_key_generate_id: Construct an asymmetric key ID
 * @val_1: First binary blob
 * @len_1: Length of first binary blob
 * @val_2: Second binary blob
 * @len_2: Length of second binary blob
 *
 * Construct an asymmetric key ID from a pair of binary blobs.
 */
struct asymmetric_key_id *asymmetric_key_generate_id(const void *val_1,
						     size_t len_1,
						     const void *val_2,
						     size_t len_2)
{
	struct asymmetric_key_id *kid;
	size_t kid_sz;
	size_t len;

	if (check_add_overflow(len_1, len_2, &len))
		return ERR_PTR(-EOVERFLOW);
	if (len > USHRT_MAX)
		return ERR_PTR(-EOVERFLOW);
	if (check_add_overflow(sizeof(struct asymmetric_key_id), len, &kid_sz))
		return ERR_PTR(-EOVERFLOW);
	kid = kmalloc(kid_sz, GFP_KERNEL);
	if (!kid)
		return ERR_PTR(-ENOMEM);
	kid->len = len;
	memcpy(kid->data, val_1, len_1);
	memcpy(kid->data + len_1, val_2, len_2);
	return kid;
}

/**
 * asymmetric_key_id_same - Return true if two asymmetric keys IDs are the same.
 * @kid1: The key ID to compare
 * @kid2: The key ID to compare
 */
bool asymmetric_key_id_same(const struct asymmetric_key_id *kid1,
			    const struct asymmetric_key_id *kid2)
{
	if (!kid1 || !kid2)
		return false;
	if (kid1->len != kid2->len)
		return false;
	return memcmp(kid1->data, kid2->data, kid1->len) == 0;
}

/**
 * asymmetric_key_id_partial - Return true if two asymmetric keys IDs
 * partially match
 * @kid1: The key ID to compare
 * @kid2: The key ID to compare
 */
bool asymmetric_key_id_partial(const struct asymmetric_key_id *kid1,
			       const struct asymmetric_key_id *kid2)
{
	if (!kid1 || !kid2)
		return false;
	if (kid1->len < kid2->len)
		return false;
	return memcmp(kid1->data + (kid1->len - kid2->len),
		      kid2->data, kid2->len) == 0;
}

/*
 * Destroy a public key signature.
 */
void public_key_signature_free(struct public_key_signature *sig)
{
	int i;

	if (sig) {
		for (i = 0; i < ARRAY_SIZE(sig->auth_ids); i++)
			kfree(sig->auth_ids[i]);
		kfree(sig->s);
		if (sig->m_free)
			kfree(sig->m);
		kfree(sig);
	}
}

struct x509_ecdsa_ctx {
	u8 *raw;
	size_t bytes;
};

static int x509_ecdsa_note_int(struct x509_ecdsa_ctx *ctx, u8 *dst,
			       const u8 *value, size_t vlen)
{
	/* Strip the sign padding, then left-pad to the size of the curve */
	while (vlen && !*value) {
		value++;
		vlen--;
	}

	if (vlen > ctx->bytes)
		return -EBADMSG;

	memcpy(dst + ctx->bytes - vlen, value, vlen);
	return 0;
}

int x509_ecdsa_note_r(void *context, size_t hdrlen, unsigned char tag,
		      const void *value, size_t vlen)
{
	struct x509_ecdsa_ctx *ctx = context;

	return x509_ecdsa_note_int(ctx, ctx->raw, value, vlen);
}

int x509_ecdsa_note_s(void *context, size_t hdrlen, unsigned char tag,
		      const void *value, size_t vlen)
{
	struct x509_ecdsa_ctx *ctx = context;

	return x509_ecdsa_note_int(ctx, ctx->raw + ctx->bytes, value, vlen);
}

static int public_key_verify_rsa(const struct public_key *pkey,
				 const struct public_key_signature *sig,
				 enum hash_algo algo)
{
	size_t len = pkey->rsa->len * sizeof(uint32_t);
	u8 *s;
	int ret;

	if (strcmp(sig->pkey_algo, "rsa") || strcmp(sig->encoding, "pkcs1"))
		return -EKEYREJECTED;

	/* The signature may have had leading zeroes stripped */
	if (sig->s_size > len)
		return -EBADMSG;

	s = kzalloc(len, GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	memcpy(s + len - sig->s_size, sig->s, sig->s_size);
	ret = rsa_verify(pkey->rsa, s, len, sig->m, algo);
	kfree(s);
	return ret;
}

static int public_key_verify_ecdsa(const struct public_key *pkey,
				   const struct public_key_signature *sig,
				   enum hash_algo algo)
{
	struct x509_ecdsa_ctx ctx = {};
	int ret;

	if (strcmp(sig->pkey_algo, "ecdsa") || strcmp(sig->encoding, "x962"))
		return -EKEYREJECTED;

	ctx.bytes = ecdsa_key_size(pkey->ecdsa->curve_name) / 8;
	if (!ctx.bytes)
		return -ENOPKG;

	ctx.raw = kzalloc(2 * ctx.bytes, GFP_KERNEL);
	if (!ctx.raw)
		return -ENOMEM;

	/* X9.62 signatures are DER encoded, while ecdsa_verify() wants r || s */
	ret = asn1_ber_decoder(&ecdsasignature_decoder, &ctx,
			       sig->s, sig->s_size);
	if (!ret)
		ret = ecdsa_verify(pkey->ecdsa, ctx.raw, 2 * ctx.bytes,
				   sig->m, algo);

	kfree(ctx.raw);
	return ret;
}

/**
 * public_key_verify_signature - Verify a signature using a public key.
 * @pkey: The public key to use
 * @sig: The signature, along with the digest of the signed data
 *
 * Returns 0 if the signature is valid, -ENOPKG if the signature uses
 * unsupported crypto, or some other negative error code otherwise.
 */
int public_key_verify_signature(const struct public_key *pkey,
				const struct public_key_signature *sig)
{
	struct digest *d;
	enum hash_algo algo;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (WARN_ON(!pkey || !sig || !sig->s))
		return -EINVAL;

	if (!sig->pkey_algo || !sig->encoding || !sig->hash_algo || !sig->m)
		return -ENOPKG;

	d = digest_alloc(sig->hash_algo);
	if (!d)
		return -ENOPKG;

	algo = digest_algo(d);
	ret = sig->m_size == digest_length(d) ? 0 : -EINVAL;
	digest_free(d);
	if (ret)
		return ret;

	switch (pkey->type) {
	case PUBLIC_KEY_TYPE_RSA:
		ret = public_key_verify_rsa(pkey, sig, algo);
		break;
	case PUBLIC_KEY_TYPE_ECDSA:
		ret = public_key_verify_ecdsa(pkey, sig, algo);
		break;
	default:
		ret = -ENOPKG;
	}

	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}
