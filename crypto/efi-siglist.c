// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Parsing of EFI signature lists (EFI_SIGNATURE_LIST), as stored in the
 * db and dbx variables of the EFI signature database.
 *
 * Based on security/integrity/platform_certs/ from Linux,
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "efi-siglist: " fmt

#include <common.h>
#include <digest.h>
#include <efi/types.h>
#include <linux/err.h>
#include <crypto/efi-siglist.h>
#include <crypto/public_key.h>
#include <crypto/sha.h>
#include <crypto/x509.h>

#define EFI_CERT_SHA256_GUID \
	EFI_GUID(0xc1c41626, 0x504c, 0x4092, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28)
#define EFI_CERT_X509_GUID \
	EFI_GUID(0xa5c059a1, 0x94e4, 0x4aa7, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72)
#define EFI_CERT_X509_SHA256_GUID \
	EFI_GUID(0x3bd2a492, 0x96c0, 0x4079, 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed)

static const efi_guid_t efi_cert_sha256_guid = EFI_CERT_SHA256_GUID;
static const efi_guid_t efi_cert_x509_guid = EFI_CERT_X509_GUID;
static const efi_guid_t efi_cert_x509_sha256_guid = EFI_CERT_X509_SHA256_GUID;

struct efi_signature_list {
	efi_guid_t signature_type;
	u32 signature_list_size;
	u32 signature_header_size;
	u32 signature_size;
	/* u8 signature_header[signature_header_size]; */
	/* struct efi_signature_data signatures[][signature_size]; */
} __packed;

struct efi_signature_data {
	efi_guid_t signature_owner;
	u8 signature_data[];
} __packed;

typedef void (*efi_element_handler_t)(struct keyring *kr,
				      const void *data, size_t size);

/*
 * Parse an EFI signature list looking for elements of interest.  A list is
 * made up of a series of sublists, where all the elements in a sublist are of
 * the same type, but sublists can be of different types.
 *
 * For each sublist encountered, the @get_handler_for_guid function is called
 * with the type specifier GUID and returns either a pointer to a function to
 * handle elements of that type or NULL if the type is not of interest.
 *
 * If the sublist is of interest, each element is passed to the handler
 * function in turn.
 *
 * Error EBADMSG is returned if the list doesn't parse correctly and 0 is
 * returned if the list was parsed correctly.
 */
typedef efi_element_handler_t (*efi_handler_lookup_t)(const efi_guid_t *);

static int parse_efi_signature_list(struct keyring *kr,
				    const void *data, size_t size,
				    efi_handler_lookup_t get_handler_for_guid)
{
	efi_element_handler_t handler;
	unsigned int offs = 0;

	pr_devel("-->%s(,%zu)\n", __func__, size);

	while (size > 0) {
		const struct efi_signature_data *elem;
		struct efi_signature_list list;
		size_t lsize, esize, hsize, elsize;

		if (size < sizeof(list))
			return -EBADMSG;

		memcpy(&list, data, sizeof(list));
		pr_devel("LIST[%04x] guid=%pUl ls=%x hs=%x ss=%x\n",
			 offs,
			 &list.signature_type, list.signature_list_size,
			 list.signature_header_size, list.signature_size);

		lsize = list.signature_list_size;
		hsize = list.signature_header_size;
		esize = list.signature_size;
		elsize = lsize - sizeof(list) - hsize;

		if (lsize > size) {
			pr_devel("<--%s() = -EBADMSG [overrun @%x]\n",
				 __func__, offs);
			return -EBADMSG;
		}

		if (lsize < sizeof(list) ||
		    lsize - sizeof(list) < hsize ||
		    esize < sizeof(*elem) ||
		    elsize < esize ||
		    elsize % esize != 0) {
			pr_devel("- bad size combo @%x\n", offs);
			return -EBADMSG;
		}

		handler = get_handler_for_guid(&list.signature_type);
		if (!handler) {
			data += lsize;
			size -= lsize;
			offs += lsize;
			continue;
		}

		data += sizeof(list) + hsize;
		size -= sizeof(list) + hsize;
		offs += sizeof(list) + hsize;

		for (; elsize > 0; elsize -= esize) {
			elem = data;

			pr_devel("ELEM[%04x]\n", offs);
			handler(kr, elem->signature_data,
				esize - sizeof(*elem));

			data += esize;
			size -= esize;
			offs += esize;
		}
	}

	return 0;
}

static bool efi_guid_is(const efi_guid_t *a, const efi_guid_t *b)
{
	return !memcmp(a, b, sizeof(*a));
}

static void efi_add_cert(struct keyring *kr, const void *data, size_t size)
{
	int ret;

	ret = x509_keyring_add_cert(kr, data, size);
	if (ret && ret != -EEXIST)
		pr_warn("Ignoring certificate in db: %pe\n", ERR_PTR(ret));
}

static void efi_add_sha256(struct keyring *kr, const void *data, size_t size)
{
	if (size != SHA256_DIGEST_SIZE) {
		pr_warn("Ignoring SHA256 of invalid size %zu\n", size);
		return;
	}

	keyring_add_hash(kr, HASH_ALGO_SHA256, data, size);
}

/*
 * A revoked certificate is blacklisted by the SHA256 of the whole
 * certificate, which is what public_key_is_blacklisted() checks for.
 */
static void efi_revoke_cert(struct keyring *kr, const void *data, size_t size)
{
	u8 digest[SHA256_DIGEST_SIZE];
	struct digest *d;

	d = digest_alloc_by_algo(HASH_ALGO_SHA256);
	if (!d)
		return;

	if (!digest_digest(d, data, size, digest))
		keyring_add_hash(kr, HASH_ALGO_SHA256, digest, sizeof(digest));

	digest_free(d);
}

/*
 * EFI_CERT_X509_SHA256 is the SHA256 of a revoked certificate's
 * TBSCertificate, followed by the time of revocation, which we ignore.
 */
static void efi_revoke_tbs(struct keyring *kr, const void *data, size_t size)
{
	if (size < SHA256_DIGEST_SIZE) {
		pr_warn("Ignoring X509_SHA256 of invalid size %zu\n", size);
		return;
	}

	keyring_add_hash(kr, HASH_ALGO_SHA256, data, SHA256_DIGEST_SIZE);
}

static efi_element_handler_t efi_db_handler(const efi_guid_t *type)
{
	if (efi_guid_is(type, &efi_cert_x509_guid))
		return efi_add_cert;
	if (efi_guid_is(type, &efi_cert_sha256_guid))
		return efi_add_sha256;

	return NULL;
}

static efi_element_handler_t efi_dbx_handler(const efi_guid_t *type)
{
	if (efi_guid_is(type, &efi_cert_x509_guid))
		return efi_revoke_cert;
	if (efi_guid_is(type, &efi_cert_sha256_guid))
		return efi_add_sha256;
	if (efi_guid_is(type, &efi_cert_x509_sha256_guid))
		return efi_revoke_tbs;

	return NULL;
}

/**
 * efi_siglist_load_db - Load the contents of an allow list (db)
 * @kr: The keyring to add certificates and digests to
 * @data: The EFI_SIGNATURE_LISTs
 * @size: The size of @data
 */
int efi_siglist_load_db(struct keyring *kr, const void *data, size_t size)
{
	return parse_efi_signature_list(kr, data, size, efi_db_handler);
}

/**
 * efi_siglist_load_dbx - Load the contents of a deny list (dbx)
 * @blacklist: The keyring to add digests of revoked certificates and data to
 * @data: The EFI_SIGNATURE_LISTs
 * @size: The size of @data
 */
int efi_siglist_load_dbx(struct keyring *blacklist, const void *data,
			 size_t size)
{
	return parse_efi_signature_list(blacklist, data, size, efi_dbx_handler);
}
