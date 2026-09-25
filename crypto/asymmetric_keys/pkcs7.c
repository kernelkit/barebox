// SPDX-License-Identifier: GPL-2.0-only
/*
 * Verification of detached PKCS#7 signatures against keyrings
 */

#define pr_fmt(fmt) "PKCS7: "fmt

#include <common.h>
#include <digest.h>
#include <crypto/pkcs7.h>
#include <linux/err.h>

static int pkcs7_verify_trust(struct pkcs7_message *pkcs7,
			      const struct keyring *trust_keyring,
			      const struct public_key **_key)
{
	int ret;

	/*
	 * First check that the message is self-consistent, i.e. that the
	 * data matches the signatures, and that the certificates it
	 * carries sign one another...
	 */
	ret = pkcs7_verify(pkcs7);
	if (ret)
		return ret;

	/* ...then that one of the signature chains is anchored in a key
	 * that we trust.
	 */
	return pkcs7_validate_trust(pkcs7, trust_keyring, _key);
}

/**
 * pkcs7_verify_buf - Verify a detached PKCS#7 signature over a buffer
 * @sig: The DER encoded PKCS#7 message
 * @siglen: The size of @sig
 * @data: The signed data
 * @datalen: The size of @data
 * @trust_keyring: The keys to trust
 * @_key: Where to return the trusted key that vouched for the data (or NULL)
 *
 * Returns 0 if the data is signed by a key in @trust_keyring, or by a
 * certificate chain that is anchored in it. -ENOKEY if the signature is
 * valid, but no trusted key was found, and some other negative error code
 * on invalid signatures.
 */
int pkcs7_verify_buf(const void *sig, size_t siglen,
		     const void *data, size_t datalen,
		     const struct keyring *trust_keyring,
		     const struct public_key **_key)
{
	struct pkcs7_message *pkcs7;
	int ret;

	pkcs7 = pkcs7_parse_message(sig, siglen);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = pkcs7_supply_detached_data(pkcs7, data, datalen);
	if (!ret)
		ret = pkcs7_verify_trust(pkcs7, trust_keyring, _key);

	pkcs7_free_message(pkcs7);
	return ret;
}
EXPORT_SYMBOL_GPL(pkcs7_verify_buf);

/**
 * pkcs7_verify_file - Verify a detached PKCS#7 signature over a file
 * @sig: The DER encoded PKCS#7 message
 * @siglen: The size of @sig
 * @filename: The file containing the signed data
 * @trust_keyring: The keys to trust
 * @_key: Where to return the trusted key that vouched for the data (or NULL)
 *
 * Like pkcs7_verify_buf(), but the file is digested piecewise, so it may
 * be arbitrarily large.
 */
int pkcs7_verify_file(const void *sig, size_t siglen,
		      const char *filename,
		      const struct keyring *trust_keyring,
		      const struct public_key **_key)
{
	struct pkcs7_message *pkcs7;
	const char *algo;
	struct digest *d = NULL;
	u8 *hash = NULL;
	int ret;

	pkcs7 = pkcs7_parse_message(sig, siglen);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	algo = pkcs7_get_digest_algo(pkcs7);
	if (algo)
		d = digest_alloc(algo);
	if (!d) {
		ret = -ENOPKG;
		goto out;
	}

	hash = xzalloc(digest_length(d));

	ret = digest_file(d, filename, hash, NULL);
	if (ret)
		goto out;

	ret = pkcs7_supply_detached_digest(pkcs7, algo, hash, digest_length(d));
	if (!ret)
		ret = pkcs7_verify_trust(pkcs7, trust_keyring, _key);

out:
	free(hash);
	digest_free(d);
	pkcs7_free_message(pkcs7);
	return ret;
}
EXPORT_SYMBOL_GPL(pkcs7_verify_file);
