// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Load X.509 certificates into keyrings
 */

#define pr_fmt(fmt) "X.509: "fmt

#include <common.h>
#include <base64.h>
#include <libfile.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <crypto/public_key.h>
#include <crypto/x509.h>

#define PEM_BEGIN	"-----BEGIN CERTIFICATE-----"
#define PEM_END		"-----END CERTIFICATE-----"

static const void *x509_memmem(const void *haystack, size_t hlen,
			       const char *needle)
{
	size_t nlen = strlen(needle);
	const char *p = haystack;

	for (; hlen >= nlen; p++, hlen--) {
		if (!memcmp(p, needle, nlen))
			return p;
	}

	return NULL;
}

static bool x509_keyring_has_cert(const struct keyring *kr,
				  const struct x509_certificate *cert)
{
	const struct public_key *key;

	for_each_key_in_keyring(key, kr) {
		if (key->cert &&
		    !memcmp(key->cert->fingerprint, cert->fingerprint,
			    sizeof(cert->fingerprint)))
			return true;
	}

	return false;
}

/**
 * x509_keyring_add_cert - Add a certificate's key to a keyring
 * @kr: The keyring
 * @der: The DER encoded certificate
 * @len: The size of @der
 *
 * Returns 0 if the key was added, -EEXIST if the certificate is already
 * present in the keyring, or another negative error code if it could not
 * be parsed.
 */
int x509_keyring_add_cert(struct keyring *kr, const void *der, size_t len)
{
	struct x509_certificate *cert;
	int ret;

	cert = x509_cert_parse(der, len);
	if (IS_ERR(cert))
		return PTR_ERR(cert);

	if (x509_keyring_has_cert(kr, cert)) {
		ret = -EEXIST;
		goto err;
	}

	ret = keyring_link_key(kr, cert->pub);
	if (ret)
		goto err;

	pr_debug("Loaded '%s' into %s\n", cert->subject, kr->name);
	return 0;
err:
	x509_free_certificate(cert);
	return ret;
}

static ssize_t x509_der_len(const u8 *p, size_t len)
{
	size_t hdr = 2, n, i, dlen;

	if (len < 2 || p[0] != 0x30)
		return -EBADMSG;

	dlen = p[1];
	if (dlen & 0x80) {
		n = dlen & 0x7f;
		if (!n || n > 3 || len < 2 + n)
			return -EBADMSG;

		for (dlen = 0, i = 0; i < n; i++)
			dlen = (dlen << 8) | p[2 + i];

		hdr += n;
	}

	if (dlen > len - hdr)
		return -EBADMSG;

	return hdr + dlen;
}

static int x509_load_der(struct keyring *kr, const u8 *p, size_t len)
{
	int ret, count = 0;
	ssize_t clen;

	while (len) {
		clen = x509_der_len(p, len);
		if (clen < 0)
			return clen;

		ret = x509_keyring_add_cert(kr, p, clen);
		if (!ret)
			count++;
		else if (ret != -EEXIST)
			return ret;

		p += clen;
		len -= clen;
	}

	return count;
}

static int x509_load_pem(struct keyring *kr, const char *p, size_t len)
{
	const char *begin, *end, *body;
	int ret, count = 0;
	bool found = false;
	char *b64;
	u8 *der;
	int dlen;

	while ((begin = x509_memmem(p, len, PEM_BEGIN))) {
		body = begin + strlen(PEM_BEGIN);
		len -= body - p;

		end = x509_memmem(body, len, PEM_END);
		if (!end)
			return -EBADMSG;

		found = true;
		b64 = xstrndup(body, end - body);
		der = xmalloc(end - body);

		dlen = decode_base64((char *)der, end - body, b64);
		ret = x509_keyring_add_cert(kr, der, dlen);

		free(der);
		free(b64);

		if (!ret)
			count++;
		else if (ret != -EEXIST)
			return ret;

		len -= end + strlen(PEM_END) - body;
		p = end + strlen(PEM_END);
	}

	return found ? count : -ENOENT;
}

/**
 * x509_load_certificates - Load certificates into a keyring
 * @kr: The keyring
 * @buf: One or more certificates, either PEM encoded, or as concatenated DER
 * @len: The size of @buf
 *
 * Returns the number of certificates added, which excludes those already
 * present in the keyring, or a negative error code. Certificates preceding
 * an invalid one are still added.
 */
int x509_load_certificates(struct keyring *kr, const void *buf, size_t len)
{
	if (x509_memmem(buf, len, PEM_BEGIN))
		return x509_load_pem(kr, buf, len);

	return x509_load_der(kr, buf, len);
}

/**
 * x509_load_certificate_file - Load certificates from a file into a keyring
 * @kr: The keyring
 * @path: The file holding the certificates, see x509_load_certificates()
 */
int x509_load_certificate_file(struct keyring *kr, const char *path)
{
	size_t len;
	void *buf;
	int ret;

	buf = read_file(path, &len);
	if (!buf)
		return -errno;

	ret = x509_load_certificates(kr, buf, len);
	free(buf);
	return ret;
}
