/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * X.509 certificates, as used by the PKCS#7 verifier.
 *
 * Based on the X.509 certificate parser from Linux,
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef __CRYPTO_X509_H
#define __CRYPTO_X509_H

#include <linux/types.h>
#include <linux/err.h>
#include <string.h>
#include <crypto/public_key.h>
#include <crypto/sha.h>

/*
 * Binary identifier of a certificate. The first form is the
 * concatenation of the serial number and the issuer's name (as used by
 * PKCS#7 SignerInfos and AuthorityKeyIdentifiers), the second is a
 * subjectKeyIdentifier.
 */
struct asymmetric_key_id {
	unsigned short	len;
	unsigned char	data[];
};

bool asymmetric_key_id_same(const struct asymmetric_key_id *kid1,
			    const struct asymmetric_key_id *kid2);
bool asymmetric_key_id_partial(const struct asymmetric_key_id *kid1,
			       const struct asymmetric_key_id *kid2);
struct asymmetric_key_id *asymmetric_key_generate_id(const void *val_1,
						     size_t len_1,
						     const void *val_2,
						     size_t len_2);

/*
 * Public key cryptography signature data
 */
struct public_key_signature {
	struct asymmetric_key_id *auth_ids[3];
	u8 *s;			/* Signature */
	u8 *m;			/* Digest of the signed data */
	u32 s_size;		/* Number of bytes in signature */
	u32 m_size;		/* Number of bytes in ->m */
	bool m_free;		/* T if ->m needs freeing */
	const char *pkey_algo;
	const char *hash_algo;
	const char *encoding;
};

void public_key_signature_free(struct public_key_signature *sig);
int public_key_verify_signature(const struct public_key *pkey,
				const struct public_key_signature *sig);

struct x509_certificate {
	struct x509_certificate *next;
	struct x509_certificate *signer;	/* Certificate that signed this one */
	struct public_key *pub;			/* Public key details */
	struct public_key_signature *sig;	/* Signature parameters */
	u8		sha256[SHA256_DIGEST_SIZE]; /* Hash of TBS, for blacklist purposes */
	u8		fingerprint[SHA256_DIGEST_SIZE]; /* Hash of the whole cert */
	char		*issuer;		/* Name of certificate issuer */
	char		*subject;		/* Name of certificate subject */
	struct asymmetric_key_id *id;		/* Issuer + Serial number */
	struct asymmetric_key_id *skid;		/* Subject + subjectKeyId (optional) */
	s64		valid_from;
	s64		valid_to;
	const void	*raw;			/* The whole certificate */
	unsigned	raw_size;
	const void	*tbs;			/* Signed data */
	unsigned	tbs_size;		/* Size of signed data */
	unsigned	raw_sig_size;		/* Size of signature */
	const void	*raw_sig;		/* Signature data */
	const void	*raw_serial;		/* Raw serial number in ASN.1 */
	unsigned	raw_serial_size;
	unsigned	raw_issuer_size;
	const void	*raw_issuer;		/* Raw issuer name in ASN.1 */
	const void	*raw_subject;		/* Raw subject name in ASN.1 */
	unsigned	raw_subject_size;
	unsigned	raw_skid_size;
	const void	*raw_skid;		/* Raw subjectKeyId in ASN.1 */
	const void	*raw_spki;		/* Raw SubjectPublicKeyInfo in ASN.1 */
	unsigned	raw_spki_size;
	unsigned long	key_eflags;		/* key extension flags */
#define KEY_EFLAG_CA		0	/* set if the CA basic constraints is set */
#define KEY_EFLAG_DIGITALSIG	1	/* set if the digitalSignature usage is set */
#define KEY_EFLAG_KEYCERTSIGN	2	/* set if the keyCertSign usage is set */
	unsigned	index;
	bool		seen;			/* Infinite recursion prevention */
	bool		verified;
	bool		self_signed;		/* T if self-signed (check unsupported_sig too) */
	bool		unsupported_sig;	/* T if signature uses unsupported crypto */
	bool		blacklisted;
};

/* Check whether the certificate's subject is the name in @name */
static inline bool x509_subject_is(const struct x509_certificate *cert,
				   const struct asymmetric_key_id *name)
{
	return cert->raw_subject_size == name->len &&
	       !memcmp(cert->raw_subject, name->data, name->len);
}

#ifdef CONFIG_CRYPTO_X509
struct x509_certificate *x509_cert_parse(const void *data, size_t datalen);
void x509_free_certificate(struct x509_certificate *cert);

int x509_keyring_add_cert(struct keyring *kr, const void *der, size_t len);
int x509_load_certificates(struct keyring *kr, const void *buf, size_t len);
int x509_load_certificate_file(struct keyring *kr, const char *path);
#else
static inline struct x509_certificate *x509_cert_parse(const void *data,
						       size_t datalen)
{
	return ERR_PTR(-ENOSYS);
}

static inline void x509_free_certificate(struct x509_certificate *cert)
{
}

static inline int x509_keyring_add_cert(struct keyring *kr, const void *der,
					size_t len)
{
	return -ENOSYS;
}

static inline int x509_load_certificates(struct keyring *kr, const void *buf,
					 size_t len)
{
	return -ENOSYS;
}

static inline int x509_load_certificate_file(struct keyring *kr,
					     const char *path)
{
	return -ENOSYS;
}
#endif

#endif /* __CRYPTO_X509_H */
