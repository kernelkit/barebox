// SPDX-License-Identifier: GPL-2.0-only

#include <fuzz.h>
#include <crypto/pkcs7.h>
#include <crypto/x509.h>
#include <linux/err.h>

#include "pkcs7_parser.h"

static int fuzz_x509(const u8 *data, size_t size)
{
	struct x509_certificate *cert;

	cert = x509_cert_parse(data, size);
	if (IS_ERR(cert))
		return 0;

	/* Exercise the signature decoding, e.g. of X9.62 signatures */
	public_key_verify_signature(cert->pub, cert->sig);

	x509_free_certificate(cert);
	return 0;
}
fuzz_test("x509", fuzz_x509);

static const char fuzz_pkcs7_data[] = "barebox";

static int fuzz_pkcs7(const u8 *data, size_t size)
{
	struct keyring kr = {
		.name = "fuzz",
		.links = LIST_HEAD_INIT(kr.links),
	};
	struct pkcs7_message *pkcs7;
	struct x509_certificate *cert;

	pkcs7 = pkcs7_parse_message(data, size);
	if (IS_ERR(pkcs7))
		return 0;

	if (!pkcs7->data)
		pkcs7_supply_detached_data(pkcs7, fuzz_pkcs7_data,
					   sizeof(fuzz_pkcs7_data) - 1);

	/*
	 * Trust the certificates carried in the message itself, so that
	 * the chain validation finds something to anchor to.
	 */
	for (cert = pkcs7->certs; cert; cert = cert->next)
		keyring_link_key(&kr, cert->pub);

	if (!pkcs7_verify(pkcs7))
		pkcs7_validate_trust(pkcs7, &kr, NULL);

	for (cert = pkcs7->certs; cert; cert = cert->next)
		keyring_unlink_key(&kr, cert->pub);

	pkcs7_free_message(pkcs7);
	return 0;
}
fuzz_test("pkcs7", fuzz_pkcs7);
