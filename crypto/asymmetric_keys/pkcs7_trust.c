// SPDX-License-Identifier: GPL-2.0-or-later
/* Validate the trust chain of a PKCS#7 message.
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "PKCS7: "fmt
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/asn1.h>
#include <crypto/public_key.h>
#include "pkcs7_parser.h"

static bool pkcs7_key_has_id(const struct public_key *key,
			     const struct asymmetric_key_id *id)
{
	const struct x509_certificate *cert = key->cert;

	/* Keys that don't originate from a certificate have no identity */
	if (!cert)
		return false;

	return asymmetric_key_id_same(cert->id, id) ||
	       asymmetric_key_id_same(cert->skid, id);
}

/*
 * Find a key in the given keyring by identifier.  The preferred identifier is
 * the id_0 and the fallback identifier is the id_1.  If both are given, the
 * former is matched against either of the sought key's identifiers and the
 * latter must match the found key's subjectKeyIdentifier.  If both are
 * missing, id_2 must match the subject name of the sought key's certificate.
 */
static const struct public_key *
find_asymmetric_key(const struct keyring *keyring,
		    const struct asymmetric_key_id *id_0,
		    const struct asymmetric_key_id *id_1,
		    const struct asymmetric_key_id *id_2)
{
	const struct asymmetric_key_id *lookup = id_0 ?: id_1;
	const struct public_key *key;

	if (WARN_ON(!lookup && !id_2))
		return ERR_PTR(-EINVAL);

	for_each_key_in_keyring(key, keyring) {
		/* Revoked keys are never trusted */
		if (public_key_is_blacklisted(key))
			continue;

		if (!lookup) {
			if (key->cert && x509_subject_is(key->cert, id_2))
				return key;
			continue;
		}

		if (!pkcs7_key_has_id(key, lookup))
			continue;

		if (id_0 && id_1 &&
		    !asymmetric_key_id_same(id_1, key->cert->skid)) {
			pr_debug("First ID matches, but second does not\n");
			return ERR_PTR(-EKEYREJECTED);
		}

		return key;
	}

	return ERR_PTR(-ENOKEY);
}

/*
 * Check the trust on one PKCS#7 SignedInfo block.
 */
static int pkcs7_validate_trust_one(struct pkcs7_message *pkcs7,
				    struct pkcs7_signed_info *sinfo,
				    const struct keyring *trust_keyring,
				    const struct public_key **_key)
{
	struct public_key_signature *sig = sinfo->sig;
	struct x509_certificate *x509, *last = NULL, *p;
	const struct public_key *key;
	int ret;

	kenter(",%u,", sinfo->index);

	if (sinfo->unsupported_crypto) {
		kleave(" = -ENOPKG [cached]");
		return -ENOPKG;
	}

	/* A signature by a revoked certificate can never be trusted */
	if (sinfo->blacklisted) {
		kleave(" = -ENOKEY [blacklisted]");
		return -ENOKEY;
	}

	for (x509 = sinfo->signer; x509; x509 = x509->signer) {
		if (x509->seen) {
			if (x509->verified)
				goto verified;
			kleave(" = -ENOKEY [cached]");
			return -ENOKEY;
		}
		x509->seen = true;

		/* Look to see if this certificate is present in the trusted
		 * keys.
		 */
		key = find_asymmetric_key(trust_keyring,
					  x509->id, x509->skid, NULL);
		if (!IS_ERR(key)) {
			/* One of the X.509 certificates in the PKCS#7 message
			 * is apparently the same as one we already trust.
			 * Verify that the trusted variant can also validate
			 * the signature on the descendant.
			 */
			pr_devel("sinfo %u: Cert %u as key %*phN\n",
				 sinfo->index, x509->index,
				 key->hashlen, key->hash);
			goto matched;
		}
		if (key == ERR_PTR(-ENOMEM))
			return -ENOMEM;

		 /* Self-signed certificates form roots of their own, and if we
		  * don't know them, then we can't accept them.
		  */
		if (x509->signer == x509) {
			kleave(" = -ENOKEY [unknown self-signed]");
			return -ENOKEY;
		}

		last = x509;
		sig = last->sig;
	}

	/* No match - see if the root certificate has a signer amongst the
	 * trusted keys.
	 */
	if (last && (last->sig->auth_ids[0] || last->sig->auth_ids[1] ||
		     last->sig->auth_ids[2])) {
		key = find_asymmetric_key(trust_keyring,
					  last->sig->auth_ids[0],
					  last->sig->auth_ids[1],
					  last->sig->auth_ids[2]);
		if (!IS_ERR(key)) {
			x509 = last;
			pr_devel("sinfo %u: Root cert %u signer is key %*phN\n",
				 sinfo->index, x509->index,
				 key->hashlen, key->hash);
			goto matched;
		}
		if (PTR_ERR(key) != -ENOKEY)
			return PTR_ERR(key);
	}

	/* As a last resort, see if we have a trusted public key that matches
	 * the signed info directly.
	 */
	key = find_asymmetric_key(trust_keyring,
				  sinfo->sig->auth_ids[0], NULL, NULL);
	if (!IS_ERR(key)) {
		pr_devel("sinfo %u: Direct signer is key %*phN\n",
			 sinfo->index, key->hashlen, key->hash);
		x509 = NULL;
		sig = sinfo->sig;
		goto matched;
	}
	if (PTR_ERR(key) != -ENOKEY)
		return PTR_ERR(key);

	kleave(" = -ENOKEY [no backref]");
	return -ENOKEY;

matched:
	ret = public_key_verify_signature(key, sig);
	if (ret < 0) {
		if (ret == -ENOMEM)
			return ret;
		kleave(" = -EKEYREJECTED [verify %d]", ret);
		return -EKEYREJECTED;
	}

	if (_key)
		*_key = key;

verified:
	if (x509) {
		x509->verified = true;
		for (p = sinfo->signer; p != x509; p = p->signer)
			p->verified = true;
	}
	kleave(" = 0");
	return 0;
}

/**
 * pkcs7_validate_trust - Validate PKCS#7 trust chain
 * @pkcs7: The PKCS#7 certificate to validate
 * @trust_keyring: Signing certificates to use as starting points
 * @_key: Where to return the trusted key that anchored a chain (or NULL)
 *
 * Validate that the certificate chain inside the PKCS#7 message intersects
 * keys we already know and trust.
 *
 * Returns, in order of descending priority:
 *
 *  (*) -EKEYREJECTED if a signature failed to match for which we have a valid
 *	key, or:
 *
 *  (*) 0 if at least one signature chain intersects with the keys in the trust
 *	keyring, or:
 *
 *  (*) -ENOPKG if a suitable crypto module couldn't be found for a check on a
 *	chain.
 *
 *  (*) -ENOKEY if we couldn't find a match for any of the signature chains in
 *	the message.
 *
 * May also return -ENOMEM.
 */
int pkcs7_validate_trust(struct pkcs7_message *pkcs7,
			 const struct keyring *trust_keyring,
			 const struct public_key **_key)
{
	struct pkcs7_signed_info *sinfo;
	struct x509_certificate *p;
	int cached_ret = -ENOKEY;
	int ret;

	for (p = pkcs7->certs; p; p = p->next)
		p->seen = false;

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		ret = pkcs7_validate_trust_one(pkcs7, sinfo, trust_keyring, _key);
		switch (ret) {
		case -ENOKEY:
			continue;
		case -ENOPKG:
			if (cached_ret == -ENOKEY)
				cached_ret = -ENOPKG;
			continue;
		case 0:
			cached_ret = 0;
			continue;
		default:
			return ret;
		}
	}

	return cached_ret;
}
EXPORT_SYMBOL_GPL(pkcs7_validate_trust);
