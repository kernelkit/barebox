// SPDX-License-Identifier: GPL-2.0-only
/*
 * Verification of dm-verity root hash signatures, as stored in the
 * *-verity-sig partitions described by the UAPI Group's Discoverable
 * Partitions Specification:
 *
 * https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
 *
 * Such a partition holds a JSON object, padded with NULs to the size of
 * the partition:
 *
 *   {
 *     "rootHash": "<hex encoded root hash of the verity partition>",
 *     "certificateFingerprint": "<hex encoded SHA256 of the signer's cert>",
 *     "signature": "<base64 encoded detached PKCS#7 signature>"
 *   }
 *
 * The signature covers the rootHash string, i.e. the hex encoding of the
 * root hash, not its binary representation.
 */

#define pr_fmt(fmt) "verity-sig: " fmt

#include <common.h>
#include <base64.h>
#include <jsmn.h>
#include <linux/ctype.h>
#include <linux/err.h>
#include <crypto/pkcs7.h>
#include <crypto/verity-sig.h>

static char *verity_sig_str(const char *json, const jsmntok_t *tokens,
			    const char *key)
{
	const jsmntok_t *tok;

	tok = jsmn_find_value(key, json, tokens);
	if (!tok || tok->type != JSMN_STRING)
		return NULL;

	return xstrndup(json + tok->start, jsmn_token_size(tok));
}

static bool verity_sig_is_hex(const char *s, size_t minlen)
{
	size_t len = strlen(s);

	if (len < minlen || len % 2)
		return false;

	for (; *s; s++) {
		if (!isxdigit(*s))
			return false;
	}

	return true;
}

/**
 * verity_sig_parse - Parse a verity signature document
 * @buf: The contents of the signature partition
 * @len: The size of @buf
 * @sig: The signature document to fill in
 *
 * Returns 0 on success, in which case the caller must release @sig with
 * verity_sig_free(), or a negative error code.
 */
int verity_sig_parse(const void *buf, size_t len, struct verity_sig *sig)
{
	const char *json = buf;
	jsmntok_t *tokens;
	unsigned int ntokens;
	char *b64 = NULL;
	int ret = -EBADMSG;

	memset(sig, 0, sizeof(*sig));

	/* The document is padded with NULs to the size of the partition */
	len = strnlen(json, len);
	if (!len)
		return -ENODATA;

	tokens = jsmn_parse_alloc(json, len, &ntokens);
	if (!tokens)
		return -EBADMSG;

	if (tokens[0].type != JSMN_OBJECT)
		goto out;

	sig->root_hash = verity_sig_str(json, tokens, "rootHash");
	if (!sig->root_hash || !verity_sig_is_hex(sig->root_hash, 2)) {
		pr_err("Missing or invalid rootHash\n");
		goto out;
	}

	sig->fingerprint = verity_sig_str(json, tokens, "certificateFingerprint");
	if (sig->fingerprint && !verity_sig_is_hex(sig->fingerprint, 2)) {
		pr_err("Invalid certificateFingerprint\n");
		goto out;
	}

	b64 = verity_sig_str(json, tokens, "signature");
	if (!b64 || !*b64) {
		pr_err("Missing signature\n");
		goto out;
	}

	sig->pkcs7 = xmalloc(strlen(b64));
	sig->pkcs7_len = decode_base64(sig->pkcs7, strlen(b64), b64);
	if (sig->pkcs7_len <= 0) {
		pr_err("Invalid signature encoding\n");
		goto out;
	}

	ret = 0;
out:
	free(b64);
	free(tokens);
	if (ret)
		verity_sig_free(sig);
	return ret;
}

void verity_sig_free(struct verity_sig *sig)
{
	free(sig->root_hash);
	free(sig->fingerprint);
	free(sig->pkcs7);
	memset(sig, 0, sizeof(*sig));
}

/**
 * verity_sig_verify - Verify a verity signature document
 * @buf: The contents of the signature partition
 * @len: The size of @buf
 * @trust_keyring: The keys to trust
 * @root_hash: Where to return the verified root hash, as an allocated hex
 *             string, to be freed by the caller
 * @_key: Where to return the trusted key that vouched for the root hash (or
 *        NULL)
 *
 * Returns 0 if the root hash is vouched for by a key in @trust_keyring,
 * or a negative error code.
 */
int verity_sig_verify(const void *buf, size_t len,
		      const struct keyring *trust_keyring,
		      char **root_hash, const struct public_key **_key)
{
	struct verity_sig sig;
	int ret;

	ret = verity_sig_parse(buf, len, &sig);
	if (ret)
		return ret;

	ret = pkcs7_verify_buf(sig.pkcs7, sig.pkcs7_len,
			       sig.root_hash, strlen(sig.root_hash),
			       trust_keyring, _key);
	if (!ret) {
		*root_hash = sig.root_hash;
		sig.root_hash = NULL;
	}

	verity_sig_free(&sig);
	return ret;
}
