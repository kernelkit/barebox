// SPDX-License-Identifier: GPL-2.0-only
/*
 * Verification of detached PKCS#7 signatures against keyrings
 */

#define pr_fmt(fmt) "PKCS7: "fmt

#include <common.h>
#include <digest.h>
#include <crypto/pkcs7.h>
#include <crypto/sha.h>
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

static int pkcs7_check_hash(const u8 *digest,
			    const struct keyring *trust_keyring)
{
	if (blacklist_has_hash(HASH_ALGO_SHA256, digest, SHA256_DIGEST_SIZE)) {
		pr_err("Data is blacklisted\n");
		return -EKEYREJECTED;
	}

	if (keyring_has_hash(trust_keyring, HASH_ALGO_SHA256, digest,
			     SHA256_DIGEST_SIZE))
		return 0;

	return -ENOKEY;
}

/*
 * Combine the result of the signature verification with the result of
 * checking the data's digest: a blacklisted digest always wins, and a
 * vouched for digest is enough, when there is no trusted signature.
 */
static int pkcs7_combine(int ret, int hret, const struct public_key **_key)
{
	if (ret && ret != -ENOKEY)
		return ret;

	if (hret == -EKEYREJECTED || (ret && !hret)) {
		if (_key)
			*_key = NULL;
		return hret;
	}

	return ret;
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
 *
 * Additionally, the SHA256 of the data is checked against the digests in
 * the blacklist, which always causes it to be rejected, and those in
 * @trust_keyring, which causes it to be accepted regardless of its
 * signature, in which case *@_key is set to NULL. If @sig is NULL, only
 * the digests are considered.
 */
int pkcs7_verify_buf(const void *sig, size_t siglen,
		     const void *data, size_t datalen,
		     const struct keyring *trust_keyring,
		     const struct public_key **_key)
{
	u8 digest[SHA256_DIGEST_SIZE];
	struct pkcs7_message *pkcs7;
	struct digest *d;
	int ret = -ENOKEY;

	if (_key)
		*_key = NULL;

	d = digest_alloc_by_algo(HASH_ALGO_SHA256);
	if (!d)
		return -ENOPKG;
	ret = digest_digest(d, data, datalen, digest);
	digest_free(d);
	if (ret)
		return ret;

	if (sig) {
		pkcs7 = pkcs7_parse_message(sig, siglen);
		if (IS_ERR(pkcs7))
			return PTR_ERR(pkcs7);

		ret = pkcs7_supply_detached_data(pkcs7, data, datalen);
		if (!ret)
			ret = pkcs7_verify_trust(pkcs7, trust_keyring, _key);

		pkcs7_free_message(pkcs7);
	} else {
		ret = -ENOKEY;
	}

	return pkcs7_combine(ret, pkcs7_check_hash(digest, trust_keyring), _key);
}
EXPORT_SYMBOL_GPL(pkcs7_verify_buf);

/*
 * Check the SHA256 of a file against the blacklist and the digests that
 * the keyring vouches for. @algo and @hash is a digest of the file that is
 * already known, and which is reused if it is a SHA256.
 */
static int pkcs7_check_file_hash(const char *filename,
				 const struct keyring *trust_keyring,
				 const char *algo, const u8 *hash)
{
	u8 digest[SHA256_DIGEST_SIZE];
	int ret;

	if (algo && hash && !strcmp(algo, "sha256")) {
		memcpy(digest, hash, sizeof(digest));
	} else {
		ret = digest_file_by_name("sha256", filename, digest, NULL);
		if (ret)
			return ret;
	}

	return pkcs7_check_hash(digest, trust_keyring);
}

/**
 * pkcs7_verify_file - Verify a detached PKCS#7 signature over a file
 * @sig: The DER encoded PKCS#7 message (or NULL)
 * @siglen: The size of @sig
 * @filename: The file containing the signed data
 * @trust_keyring: The keys to trust
 * @_key: Where to return the trusted key that vouched for the data (or NULL)
 *
 * Like pkcs7_verify_buf(), but the file is digested piecewise, so it may
 * be arbitrarily large.
 *
 * Additionally, the SHA256 of the file is checked against the digests in
 * the blacklist, which always causes it to be rejected, and those in
 * @trust_keyring, which causes it to be accepted regardless of its
 * signature, in which case *@_key is set to NULL. If @sig is NULL, only
 * the digests are considered.
 */
int pkcs7_verify_file(const void *sig, size_t siglen,
		      const char *filename,
		      const struct keyring *trust_keyring,
		      const struct public_key **_key)
{
	struct pkcs7_message *pkcs7;
	const char *algo = NULL;
	struct digest *d = NULL;
	u8 *hash = NULL;
	int ret;

	if (_key)
		*_key = NULL;

	if (!sig)
		return pkcs7_check_file_hash(filename, trust_keyring, NULL, NULL);

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

	/* The SHA256 may be blacklisted, or vouched for, on its own */
	if (!ret || ret == -ENOKEY)
		ret = pkcs7_combine(ret, pkcs7_check_file_hash(filename,
							       trust_keyring,
							       algo, hash),
				    _key);

out:
	free(hash);
	digest_free(d);
	pkcs7_free_message(pkcs7);
	return ret;
}
EXPORT_SYMBOL_GPL(pkcs7_verify_file);
