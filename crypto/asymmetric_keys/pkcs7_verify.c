// SPDX-License-Identifier: GPL-2.0-or-later
/* Verify the signature on a PKCS#7 message.
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "PKCS7: "fmt
#include <common.h>
#include <digest.h>
#include <fuzz.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/asn1.h>
#include <linux/bitops.h>
#include <crypto/public_key.h>
#include "pkcs7_parser.h"

/*
 * Digest the relevant parts of the PKCS#7 data
 */
static int pkcs7_digest(struct pkcs7_message *pkcs7,
			struct pkcs7_signed_info *sinfo)
{
	struct public_key_signature *sig = sinfo->sig;
	struct digest *d;
	int ret;

	kenter(",%u,%s", sinfo->index, sinfo->sig->hash_algo);

	/* The digest was calculated already. */
	if (sig->m)
		return 0;

	if (!sinfo->sig->hash_algo)
		return -ENOPKG;

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	d = digest_alloc(sinfo->sig->hash_algo);
	if (!d)
		return -ENOPKG;

	sig->m_size = digest_length(d);

	ret = -ENOMEM;
	sig->m = kmalloc(max_t(size_t, sinfo->authattrs_len, sig->m_size),
			 GFP_KERNEL);
	if (!sig->m)
		goto error;
	sig->m_free = true;

	/* Digest the message [RFC2315 9.3] */
	if (pkcs7->data) {
		ret = digest_digest(d, pkcs7->data, pkcs7->data_len, sig->m);
		if (ret < 0)
			goto error;
	} else if (pkcs7->digest) {
		/*
		 * The caller has digested the (possibly very large) detached
		 * data on our behalf.
		 */
		if (strcmp(pkcs7->digest_algo, sinfo->sig->hash_algo)) {
			ret = -ENOPKG;
			goto error;
		}

		if (pkcs7->digest_len != sig->m_size) {
			ret = -EINVAL;
			goto error;
		}

		memcpy(sig->m, pkcs7->digest, sig->m_size);
	} else {
		pr_warn("Sig %u: No data to verify\n", sinfo->index);
		ret = -ENODATA;
		goto error;
	}
	pr_devel("MsgDigest = [%*ph]\n", 8, sig->m);

	if (blacklist_has_hash(digest_algo(d), sig->m, sig->m_size)) {
		pr_warn("Sig %u: Data is blacklisted\n", sinfo->index);
		ret = -EKEYREJECTED;
		goto error;
	}

	/* However, if there are authenticated attributes, there must be a
	 * message digest attribute amongst them which corresponds to the
	 * digest we just calculated.
	 */
	if (sinfo->authattrs) {
		if (!sinfo->msgdigest) {
			pr_warn("Sig %u: No messageDigest\n", sinfo->index);
			ret = -EKEYREJECTED;
			goto error;
		}

		if (sinfo->msgdigest_len != sig->m_size) {
			pr_warn("Sig %u: Invalid digest size (%u)\n",
				sinfo->index, sinfo->msgdigest_len);
			ret = -EBADMSG;
			goto error;
		}

		if (memcmp(sig->m, sinfo->msgdigest,
			   sinfo->msgdigest_len) != 0 &&
		    !fuzz_insecure_digest_accepted(sig->m, sinfo->msgdigest,
						   sinfo->msgdigest_len)) {
			pr_warn("Sig %u: Message digest doesn't match\n",
				sinfo->index);
			ret = -EKEYREJECTED;
			goto error;
		}

		/* We then calculate anew, using the authenticated attributes
		 * as the contents of the digest instead.  Note that we need to
		 * convert the attributes from a CONT.0 into a SET before we
		 * hash it.
		 */
		memcpy(sig->m, sinfo->authattrs, sinfo->authattrs_len);
		sig->m[0] = ASN1_CONS_BIT | ASN1_SET;

		ret = digest_digest(d, sig->m, sinfo->authattrs_len, sig->m);
		if (ret < 0)
			goto error;
		pr_devel("AADigest = [%*ph]\n", 8, sig->m);
	}

	ret = 0;
error:
	if (ret && sig->m_free) {
		kfree(sig->m);
		sig->m = NULL;
		sig->m_free = false;
	}
	digest_free(d);
	kleave(" = %d", ret);
	return ret;
}

/**
 * pkcs7_get_digest_algo - Get the digest algorithm of a PKCS#7 message
 * @pkcs7: The PKCS#7 message
 *
 * Get the name of the digest algorithm used by the first signature of the
 * message, i.e. the one the detached data should be digested with before
 * passing it to pkcs7_supply_detached_digest().
 */
const char *pkcs7_get_digest_algo(const struct pkcs7_message *pkcs7)
{
	if (!pkcs7->signed_infos)
		return NULL;

	return pkcs7->signed_infos->sig->hash_algo;
}
EXPORT_SYMBOL_GPL(pkcs7_get_digest_algo);

/*
 * Find the key (X.509 certificate) to use to verify a PKCS#7 message.  PKCS#7
 * uses the issuer's name and the issuing certificate serial number for
 * matching purposes.  These must match the certificate issuer's name (not
 * subject's name) and the certificate serial number [RFC 2315 6.7].
 */
static int pkcs7_find_key(struct pkcs7_message *pkcs7,
			  struct pkcs7_signed_info *sinfo)
{
	struct x509_certificate *x509;
	unsigned certix = 1;

	kenter("%u", sinfo->index);

	for (x509 = pkcs7->certs; x509; x509 = x509->next, certix++) {
		/* I'm _assuming_ that the generator of the PKCS#7 message will
		 * encode the fields from the X.509 cert in the same way in the
		 * PKCS#7 message - but I can't be 100% sure of that.  It's
		 * possible this will need element-by-element comparison.
		 */
		/*
		 * Unlike Linux, we also support CMS version 3 SignerInfos,
		 * where the signer is identified by its subjectKeyIdentifier.
		 */
		if (!asymmetric_key_id_same(x509->id, sinfo->sig->auth_ids[0]) &&
		    !asymmetric_key_id_same(x509->skid, sinfo->sig->auth_ids[0]))
			continue;
		pr_devel("Sig %u: Found cert serial match X.509[%u]\n",
			 sinfo->index, certix);

		sinfo->signer = x509;
		return 0;
	}

	/* The relevant X.509 cert isn't found here, but it might be found in
	 * the trust keyring.
	 */
	pr_debug("Sig %u: Issuing X.509 cert not found (#%*phN)\n",
		 sinfo->index,
		 sinfo->sig->auth_ids[0]->len, sinfo->sig->auth_ids[0]->data);
	return 0;
}

/*
 * Verify the internal certificate chain as best we can.
 */
static int pkcs7_verify_sig_chain(struct pkcs7_message *pkcs7,
				  struct pkcs7_signed_info *sinfo)
{
	struct public_key_signature *sig;
	struct x509_certificate *x509 = sinfo->signer, *p;
	struct asymmetric_key_id *auth;
	int ret;

	kenter("");

	for (p = pkcs7->certs; p; p = p->next)
		p->seen = false;

	for (;;) {
		pr_debug("verify %s: %*phN\n",
			 x509->subject,
			 x509->raw_serial_size, x509->raw_serial);
		x509->seen = true;

		if (x509->blacklisted) {
			/* If this cert is blacklisted, then mark everything
			 * that depends on this as blacklisted too.
			 */
			sinfo->blacklisted = true;
			for (p = sinfo->signer; p != x509; p = p->signer)
				p->blacklisted = true;
			pr_debug("- blacklisted\n");
			return 0;
		}

		pr_debug("- issuer %s\n", x509->issuer);
		sig = x509->sig;
		if (sig->auth_ids[0])
			pr_debug("- authkeyid.id %*phN\n",
				 sig->auth_ids[0]->len, sig->auth_ids[0]->data);
		if (sig->auth_ids[1])
			pr_debug("- authkeyid.skid %*phN\n",
				 sig->auth_ids[1]->len, sig->auth_ids[1]->data);

		if (x509->self_signed) {
			/* If there's no authority certificate specified, then
			 * the certificate must be self-signed and is the root
			 * of the chain.  Likewise if the cert is its own
			 * authority.
			 */
			if (x509->unsupported_sig)
				goto unsupported_sig_in_x509;
			x509->signer = x509;
			pr_debug("- self-signed\n");
			return 0;
		}

		/* Look through the X.509 certificates in the PKCS#7 message's
		 * list to see if the next one is there.
		 */
		auth = sig->auth_ids[0];
		if (auth) {
			pr_debug("- want %*phN\n", auth->len, auth->data);
			for (p = pkcs7->certs; p; p = p->next) {
				pr_debug("- cmp [%u] %*phN\n",
					 p->index, p->id->len, p->id->data);
				if (asymmetric_key_id_same(p->id, auth))
					goto found_issuer_check_skid;
			}
		} else if (sig->auth_ids[1]) {
			auth = sig->auth_ids[1];
			pr_debug("- want %*phN\n", auth->len, auth->data);
			for (p = pkcs7->certs; p; p = p->next) {
				if (!p->skid)
					continue;
				pr_debug("- cmp [%u] %*phN\n",
					 p->index, p->skid->len, p->skid->data);
				if (asymmetric_key_id_same(p->skid, auth))
					goto found_issuer;
			}
		} else if (sig->auth_ids[2]) {
			/*
			 * Unlike Linux, we fall back to matching the issuer's
			 * name, as certificates without an AKID (e.g. X.509v1
			 * ones) are still in use.
			 */
			auth = sig->auth_ids[2];
			pr_debug("- want name %*phN\n", auth->len, auth->data);
			for (p = pkcs7->certs; p; p = p->next) {
				if (x509_subject_is(p, auth))
					goto found_issuer;
			}
		}

		/* We didn't find the root of this chain */
		pr_debug("- top\n");
		return 0;

	found_issuer_check_skid:
		/* We matched issuer + serialNumber, but if there's an
		 * authKeyId.keyId, that must match the CA subjKeyId also.
		 */
		if (sig->auth_ids[1] &&
		    !asymmetric_key_id_same(p->skid, sig->auth_ids[1])) {
			pr_warn("Sig %u: X.509 chain contains auth-skid nonmatch (%u->%u)\n",
				sinfo->index, x509->index, p->index);
			return -EKEYREJECTED;
		}
	found_issuer:
		pr_debug("- subject %s\n", p->subject);
		if (p->seen) {
			pr_warn("Sig %u: X.509 chain contains loop\n",
				sinfo->index);
			return 0;
		}
		ret = public_key_verify_signature(p->pub, x509->sig);
		if (ret < 0)
			return ret;
		x509->signer = p;
		if (x509 == p) {
			pr_debug("- self-signed\n");
			return 0;
		}
		x509 = p;
	}

unsupported_sig_in_x509:
	/* Just prune the certificate chain at this point if we lack some
	 * crypto module to go further.  Note, however, we don't want to set
	 * sinfo->unsupported_crypto as the signed info block may still be
	 * validatable against an X.509 cert lower in the chain that we have a
	 * trusted copy of.
	 */
	return 0;
}

/*
 * Verify one signed information block from a PKCS#7 message.
 */
static int pkcs7_verify_one(struct pkcs7_message *pkcs7,
			    struct pkcs7_signed_info *sinfo)
{
	int ret;

	kenter(",%u", sinfo->index);

	/* First of all, digest the data in the PKCS#7 message and the
	 * signed information block
	 */
	ret = pkcs7_digest(pkcs7, sinfo);
	if (ret < 0)
		return ret;

	/* Find the key for the signature if there is one */
	ret = pkcs7_find_key(pkcs7, sinfo);
	if (ret < 0)
		return ret;

	if (!sinfo->signer)
		return 0;

	pr_devel("Using X.509[%u] for sig %u\n",
		 sinfo->signer->index, sinfo->index);

	/* Check that the PKCS#7 signing time is valid according to the X.509
	 * certificate.  We can't, however, check against the system clock
	 * since that may not have been set yet and may be wrong.
	 */
	if (test_bit(sinfo_has_signing_time, &sinfo->aa_set)) {
		if (sinfo->signing_time < sinfo->signer->valid_from ||
		    sinfo->signing_time > sinfo->signer->valid_to) {
			pr_warn("Message signed outside of X.509 validity window\n");
			return -EKEYREJECTED;
		}
	}

	/* Verify the PKCS#7 binary against the key */
	ret = public_key_verify_signature(sinfo->signer->pub, sinfo->sig);
	if (ret < 0)
		return ret;

	pr_devel("Verified signature %u\n", sinfo->index);

	/* Verify the internal certificate chain */
	return pkcs7_verify_sig_chain(pkcs7, sinfo);
}

/**
 * pkcs7_verify - Verify a PKCS#7 message
 * @pkcs7: The PKCS#7 message to be verified
 *
 * Verify a PKCS#7 message is internally consistent - that is, the data digest
 * matches the digest in the AuthAttrs and any signature in the message or one
 * of the X.509 certificates it carries that matches another X.509 cert in the
 * message can be verified.
 *
 * This does not look to match the contents of the PKCS#7 message against any
 * external public keys.
 *
 * Returns, in order of descending priority:
 *
 *  (*) -EKEYREJECTED if the content is not pkcs7-data, or:
 *
 *  (*) -EKEYREJECTED if a signature failed to match for which we found an
 *	appropriate X.509 certificate, or:
 *
 *  (*) -EBADMSG if some part of the message was invalid, or:
 *
 *  (*) 0 if a signature chain passed verification, or:
 *
 *  (*) -EKEYREJECTED if a blacklisted key was encountered, or:
 *
 *  (*) -ENOPKG if none of the signature chains are verifiable because suitable
 *	crypto modules couldn't be found.
 */
int pkcs7_verify(struct pkcs7_message *pkcs7)
{
	struct pkcs7_signed_info *sinfo;
	int actual_ret = -ENOPKG;
	int ret;

	kenter("");

	if (pkcs7->data_type != OID_data) {
		pr_warn("Invalid sig (not pkcs7-data)\n");
		return -EKEYREJECTED;
	}

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		ret = pkcs7_verify_one(pkcs7, sinfo);
		if (sinfo->blacklisted) {
			if (actual_ret == -ENOPKG)
				actual_ret = -EKEYREJECTED;
			continue;
		}
		if (ret < 0) {
			if (ret == -ENOPKG) {
				sinfo->unsupported_crypto = true;
				continue;
			}
			kleave(" = %d", ret);
			return ret;
		}
		actual_ret = 0;
	}

	kleave(" = %d", actual_ret);
	return actual_ret;
}
EXPORT_SYMBOL_GPL(pkcs7_verify);

/**
 * pkcs7_supply_detached_data - Supply the data needed to verify a PKCS#7 message
 * @pkcs7: The PKCS#7 message
 * @data: The data to be verified
 * @datalen: The amount of data
 *
 * Supply the detached data needed to verify a PKCS#7 message.  Note that no
 * attempt to retain/pin the data is made.  That is left to the caller.  The
 * data will not be modified by pkcs7_verify() and will not be freed when the
 * PKCS#7 message is freed.
 *
 * Returns -EINVAL if data is already supplied in the message, 0 otherwise.
 */
int pkcs7_supply_detached_data(struct pkcs7_message *pkcs7,
			       const void *data, size_t datalen)
{
	if (pkcs7->data || pkcs7->digest) {
		pr_warn("Data already supplied\n");
		return -EINVAL;
	}
	pkcs7->data = data;
	pkcs7->data_len = datalen;
	return 0;
}
EXPORT_SYMBOL_GPL(pkcs7_supply_detached_data);

/**
 * pkcs7_supply_detached_digest - Supply the digest of the detached data
 * @pkcs7: The PKCS#7 message
 * @hash_algo: The name of the digest algorithm used
 * @digest: The digest of the data to be verified
 * @len: The size of the digest
 *
 * Instead of supplying the detached data itself, which would have to be
 * held in memory in its entirety, supply its digest. The algorithm must
 * match the one used by the signatures in the message, see
 * pkcs7_get_digest_algo(); signatures that use another algorithm are
 * treated as unsupported.
 *
 * As with pkcs7_supply_detached_data(), the digest is not copied.
 *
 * Returns -EINVAL if data is already supplied in the message, 0 otherwise.
 */
int pkcs7_supply_detached_digest(struct pkcs7_message *pkcs7,
				 const char *hash_algo,
				 const u8 *digest, size_t len)
{
	if (pkcs7->data || pkcs7->digest) {
		pr_warn("Data already supplied\n");
		return -EINVAL;
	}
	pkcs7->digest_algo = hash_algo;
	pkcs7->digest = digest;
	pkcs7->digest_len = len;
	return 0;
}
EXPORT_SYMBOL_GPL(pkcs7_supply_detached_digest);
