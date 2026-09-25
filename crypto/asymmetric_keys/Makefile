# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_CRYPTO_X509) += \
	x509.asn1.o \
	x509_akid.asn1.o \
	rsapubkey.asn1.o \
	ecdsasignature.asn1.o \
	x509_cert_parser.o \
	x509_public_key.o \
	x509_loader.o \
	signature.o

obj-$(CONFIG_CRYPTO_PKCS7) += \
	pkcs7.asn1.o \
	pkcs7_parser.o \
	pkcs7_verify.o \
	pkcs7_trust.o \
	pkcs7.o

$(obj)/x509_cert_parser.o: \
	$(obj)/x509.asn1.h \
	$(obj)/x509_akid.asn1.h
$(obj)/x509_public_key.o: $(obj)/rsapubkey.asn1.h
$(obj)/signature.o: $(obj)/ecdsasignature.asn1.h
$(obj)/pkcs7_parser.o: $(obj)/pkcs7.asn1.h
