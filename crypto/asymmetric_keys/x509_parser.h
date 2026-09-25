/* SPDX-License-Identifier: GPL-2.0-or-later */
/* X.509 certificate parser internal definitions
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/cleanup.h>
#include <linux/oid_registry.h>
#include <crypto/public_key.h>
#include <crypto/x509.h>

/*
 * x509_cert_parser.c
 */
DEFINE_FREE(x509_free_certificate, struct x509_certificate *,
	    if (!IS_ERR(_T)) x509_free_certificate(_T))
extern int x509_decode_time(s64 *_t,  size_t hdrlen,
			    unsigned char tag,
			    const unsigned char *value, size_t vlen);

/*
 * x509_public_key.c
 */
extern int x509_get_sig_params(struct x509_certificate *cert);
extern int x509_check_for_self_signed(struct x509_certificate *cert);
extern int x509_public_key_hash(struct x509_certificate *cert);
extern struct public_key *x509_public_key_create(enum OID algo,
						 const void *params, size_t paramlen,
						 const void *key, size_t keylen);
extern void public_key_free(struct public_key *key);
