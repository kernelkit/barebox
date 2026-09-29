/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __CRYPTO_VERITY_SIG_H
#define __CRYPTO_VERITY_SIG_H

#include <linux/types.h>
#include <crypto/public_key.h>

struct verity_sig {
	char *root_hash;	/* Hex encoded root hash */
	char *fingerprint;	/* Hex encoded SHA256 of signer cert (optional) */
	void *pkcs7;		/* DER encoded PKCS#7 signature */
	int pkcs7_len;
};

int verity_sig_parse(const void *buf, size_t len, struct verity_sig *sig);
void verity_sig_free(struct verity_sig *sig);

int verity_sig_verify(const void *buf, size_t len,
		      const struct keyring *trust_keyring,
		      char **root_hash, const struct public_key **_key);

#ifdef CONFIG_CRYPTO_VERITY_SIG
bool verity_sig_root_hash_is_trusted(const void *digest, size_t len);
#else
static inline bool verity_sig_root_hash_is_trusted(const void *digest,
						   size_t len)
{
	return false;
}
#endif

#endif /* __CRYPTO_VERITY_SIG_H */
