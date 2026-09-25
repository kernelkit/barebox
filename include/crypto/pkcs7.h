/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PKCS#7 crypto data parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _CRYPTO_PKCS7_H
#define _CRYPTO_PKCS7_H

#include <linux/err.h>
#include <crypto/public_key.h>

struct keyring;
struct pkcs7_message;

#ifdef CONFIG_CRYPTO_PKCS7
/*
 * pkcs7_parser.c
 */
extern struct pkcs7_message *pkcs7_parse_message(const void *data,
						 size_t datalen);
extern void pkcs7_free_message(struct pkcs7_message *pkcs7);

extern int pkcs7_get_content_data(const struct pkcs7_message *pkcs7,
				  const void **_data, size_t *_datalen,
				  size_t *_headerlen);

/*
 * pkcs7_trust.c
 */
extern int pkcs7_validate_trust(struct pkcs7_message *pkcs7,
				const struct keyring *trust_keyring,
				const struct public_key **_key);

/*
 * pkcs7_verify.c
 */
extern int pkcs7_verify(struct pkcs7_message *pkcs7);

extern int pkcs7_supply_detached_data(struct pkcs7_message *pkcs7,
				      const void *data, size_t datalen);

extern const char *pkcs7_get_digest_algo(const struct pkcs7_message *pkcs7);

extern int pkcs7_supply_detached_digest(struct pkcs7_message *pkcs7,
					const char *hash_algo,
					const u8 *digest, size_t len);

/*
 * pkcs7.c
 */
extern int pkcs7_verify_buf(const void *sig, size_t siglen,
			    const void *data, size_t datalen,
			    const struct keyring *trust_keyring,
			    const struct public_key **_key);

extern int pkcs7_verify_file(const void *sig, size_t siglen,
			     const char *filename,
			     const struct keyring *trust_keyring,
			     const struct public_key **_key);
#else
static inline int pkcs7_verify_buf(const void *sig, size_t siglen,
				   const void *data, size_t datalen,
				   const struct keyring *trust_keyring,
				   const struct public_key **_key)
{
	return -ENOSYS;
}

static inline int pkcs7_verify_file(const void *sig, size_t siglen,
				    const char *filename,
				    const struct keyring *trust_keyring,
				    const struct public_key **_key)
{
	return -ENOSYS;
}
#endif

#endif /* _CRYPTO_PKCS7_H */
