// SPDX-License-Identifier: GPL-2.0-only

#include <command.h>
#include <complete.h>
#include <environment.h>
#include <getopt.h>
#include <libfile.h>
#include <stdio.h>
#include <crypto/pkcs7.h>
#include <crypto/public_key.h>
#include <crypto/verity-sig.h>
#include <crypto/x509.h>
#include <linux/err.h>

static const struct keyring *pkcs7_keyring(const char *name)
{
	const struct keyring *kr;

	kr = keyring_find(name);
	if (!kr)
		printf("%s: no such keyring\n", name);

	return kr;
}

static int pkcs7_report(const char *what, int ret,
			const struct public_key *key, bool verbose)
{
	switch (ret) {
	case 0:
		if (!verbose)
			break;

		printf("%s: OK, vouched for by ", what);
		if (!key)
			printf("its digest");
		else if (key->cert)
			printf("\"%s\"", key->cert->subject);
		else
			printf("%*phN", key->hashlen, key->hash);
		printf("\n");
		break;
	case -ENOKEY:
		printf("%s: not signed by any trusted key\n", what);
		break;
	case -EKEYREJECTED:
		printf("%s: invalid signature\n", what);
		break;
	case -ENOPKG:
		printf("%s: unsupported algorithm\n", what);
		break;
	default:
		printf("%s: verification failed: %pe\n", what, ERR_PTR(ret));
		break;
	}

	return ret ? COMMAND_ERROR : COMMAND_SUCCESS;
}

static int pkcs7_cmd_verify(int argc, char *argv[], bool verbose)
{
	const struct public_key *key = NULL;
	const struct keyring *kr;
	size_t siglen;
	void *sig;
	int ret;

	if (argc != 2 && argc != 3)
		return COMMAND_ERROR_USAGE;

	kr = pkcs7_keyring(argv[0]);
	if (!kr)
		return COMMAND_ERROR;

	if (argc == 2) {
		/* Only the digests the keyring vouches for are considered */
		sig = NULL;
		siglen = 0;
	} else {
		sig = read_file(argv[2], &siglen);
		if (!sig) {
			printf("%s: %m\n", argv[2]);
			return COMMAND_ERROR;
		}
	}

	ret = pkcs7_verify_file(sig, siglen, argv[1], kr, &key);
	free(sig);

	return pkcs7_report(argv[1], ret, key, verbose);
}

static int pkcs7_cmd_verify_ddi(int argc, char *argv[], bool verbose,
				const char *var)
{
	const struct public_key *key = NULL;
	const struct keyring *kr;
	char *root_hash = NULL;
	size_t len;
	void *buf;
	int ret;

	if (argc != 2)
		return COMMAND_ERROR_USAGE;

	kr = pkcs7_keyring(argv[0]);
	if (!kr)
		return COMMAND_ERROR;

	buf = read_file(argv[1], &len);
	if (!buf) {
		printf("%s: %m\n", argv[1]);
		return COMMAND_ERROR;
	}

	ret = verity_sig_verify(buf, len, kr, &root_hash, &key);
	free(buf);

	ret = pkcs7_report(argv[1], ret, key, verbose);
	if (ret)
		return ret;

	if (var)
		ret = setenv(var, root_hash) ? COMMAND_ERROR : COMMAND_SUCCESS;
	else if (verbose)
		printf("rootHash: %s\n", root_hash);

	free(root_hash);
	return ret;
}

static int do_pkcs7(int argc, char *argv[])
{
	const char *cmd, *var = NULL;
	bool verbose = false;
	int opt;

	while ((opt = getopt(argc, argv, "vs:")) > 0) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 's':
			var = optarg;
			break;
		default:
			return COMMAND_ERROR_USAGE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		return COMMAND_ERROR_USAGE;

	cmd = argv[0];
	argc--;
	argv++;

	if (!strcmp(cmd, "verify"))
		return pkcs7_cmd_verify(argc, argv, verbose);

	if (IS_ENABLED(CONFIG_CRYPTO_VERITY_SIG) && !strcmp(cmd, "verify-ddi"))
		return pkcs7_cmd_verify_ddi(argc, argv, verbose, var);

	printf("Unknown command: %s\n", cmd);
	return COMMAND_ERROR_USAGE;
}

BAREBOX_CMD_HELP_START(pkcs7)
BAREBOX_CMD_HELP_TEXT("Verify detached PKCS#7 signatures against the keys in KEYRING.")
BAREBOX_CMD_HELP_TEXT("A signature is accepted if it was made by a key in KEYRING, or")
BAREBOX_CMD_HELP_TEXT("by a certificate that chains up to one, using the certificates")
BAREBOX_CMD_HELP_TEXT("carried in the signature. Data can also be vouched for by the")
BAREBOX_CMD_HELP_TEXT("SHA256 digests in KEYRING (e.g. EFI db), and is always rejected")
BAREBOX_CMD_HELP_TEXT("if its digest is blacklisted (e.g. by EFI dbx).")
BAREBOX_CMD_HELP_TEXT("")
BAREBOX_CMD_HELP_TEXT("Commands:")
BAREBOX_CMD_HELP_OPT ("verify KEYRING FILE [SIGFILE]", "verify the signature of FILE, or")
BAREBOX_CMD_HELP_OPT ("", "only its SHA256, if no SIGFILE is given")
#ifdef CONFIG_CRYPTO_VERITY_SIG
BAREBOX_CMD_HELP_OPT ("verify-ddi KEYRING SIGDEV", "verify the root hash signature in a")
BAREBOX_CMD_HELP_OPT ("", "Discoverable Disk Image *-verity-sig partition")
#endif
BAREBOX_CMD_HELP_TEXT("")
BAREBOX_CMD_HELP_TEXT("Options:")
BAREBOX_CMD_HELP_OPT ("-v", "verbose, show the key that vouched for the data")
#ifdef CONFIG_CRYPTO_VERITY_SIG
BAREBOX_CMD_HELP_OPT ("-s VAR", "verify-ddi: store the verified root hash in VAR, e.g.")
BAREBOX_CMD_HELP_OPT ("", "for use with veritysetup")
#endif
BAREBOX_CMD_HELP_END

BAREBOX_CMD_START(pkcs7)
	.cmd		= do_pkcs7,
	BAREBOX_CMD_DESC("verify PKCS#7 signatures")
	BAREBOX_CMD_OPTS("[-v] [-s VAR] COMMAND KEYRING ARGS...")
	BAREBOX_CMD_GROUP(CMD_GRP_MISC)
	BAREBOX_CMD_HELP(cmd_pkcs7_help)
	BAREBOX_CMD_COMPLETE(empty_complete)
BAREBOX_CMD_END
