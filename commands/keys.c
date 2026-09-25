#include <command.h>
#include <complete.h>
#include <getopt.h>
#include <stdio.h>
#include <crypto/public_key.h>
#include <crypto/x509.h>
#include <linux/err.h>

static struct keyring *keys_get_keyring(const char *name)
{
	struct keyring *kr;

	kr = keyring_find(name);
	if (!kr)
		kr = keyring_create(name);

	return kr;
}

static int keys_add(const char *name, int argc, char *argv[])
{
	struct keyring *kr;
	int i, ret;

	if (!IS_ENABLED(CONFIG_CRYPTO_X509)) {
		printf("X.509 support is not enabled\n");
		return -ENOSYS;
	}

	kr = keys_get_keyring(name);
	if (IS_ERR(kr))
		return PTR_ERR(kr);

	for (i = 0; i < argc; i++) {
		ret = x509_load_certificate_file(kr, argv[i]);
		if (ret < 0) {
			printf("%s: %pe\n", argv[i], ERR_PTR(ret));
			return ret;
		}
	}

	return 0;
}

static int keys_link(const char *name, const char *subname)
{
	struct keyring *kr, *sub;

	sub = keyring_find(subname);
	if (!sub) {
		printf("%s: no such keyring\n", subname);
		return -ENOENT;
	}

	kr = keys_get_keyring(name);
	if (IS_ERR(kr))
		return PTR_ERR(kr);

	return keyring_link_keyring(kr, sub);
}

static void keys_print(void)
{
	const struct keyring *kr;
	const struct keyring_link *link;

	for_each_keyring(kr) {
		printf("RING: %s\n", kr->name);

		if (!list_empty(&kr->hashes))
			printf("    HASHES: %zu\n",
			       list_count_nodes((struct list_head *)&kr->hashes));

		for_each_link_in_keyring(link, kr) {
			if (link->type == KEYRING_LINK_KEY) {
				const struct public_key *key = link->key;

				printf("    KEY:    %*phN\tTYPE: %s\tHINT: %s\n",
				       key->hashlen, key->hash,
				       public_key_type_string(key->type),
				       key->key_name_hint ?: "");

				if (key->cert)
					printf("            SUBJECT: %s\tISSUER: %s\n",
					       key->cert->subject,
					       key->cert->issuer);
			} else {
				printf("    RING:   %s\n", link->keyring->name);
			}
		}
	}
}

static int do_keys(int argc, char *argv[])
{
	const char *add = NULL, *link = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "a:l:")) > 0) {
		switch (opt) {
		case 'a':
			add = optarg;
			break;
		case 'l':
			link = optarg;
			break;
		default:
			return COMMAND_ERROR_USAGE;
		}
	}

	argc -= optind;
	argv += optind;

	if (add && link)
		return COMMAND_ERROR_USAGE;

	if (add) {
		if (argc < 1)
			return COMMAND_ERROR_USAGE;

		return keys_add(add, argc, argv) ? COMMAND_ERROR : 0;
	}

	if (link) {
		if (argc != 1)
			return COMMAND_ERROR_USAGE;

		return keys_link(link, argv[0]) ? COMMAND_ERROR : 0;
	}

	if (argc)
		return COMMAND_ERROR_USAGE;

	keys_print();
	return 0;
}

BAREBOX_CMD_HELP_START(keys)
BAREBOX_CMD_HELP_TEXT("Print information about public keys and keyrings, or")
BAREBOX_CMD_HELP_TEXT("add keys to them at runtime.")
BAREBOX_CMD_HELP_TEXT("")
BAREBOX_CMD_HELP_TEXT("Options:")
BAREBOX_CMD_HELP_OPT ("-a KEYRING FILE...", "add the X.509 certificates in FILEs (PEM or DER)")
BAREBOX_CMD_HELP_OPT ("", "to KEYRING, which is created if it does not exist")
BAREBOX_CMD_HELP_OPT ("-l KEYRING SUBRING", "trust all keys in SUBRING wherever KEYRING is trusted")
BAREBOX_CMD_HELP_END

BAREBOX_CMD_START(keys)
	.cmd		= do_keys,
	BAREBOX_CMD_DESC("Print or modify keyrings")
	BAREBOX_CMD_OPTS("[-a KEYRING FILE...] [-l KEYRING SUBRING]")
	BAREBOX_CMD_GROUP(CMD_GRP_CONSOLE)
	BAREBOX_CMD_HELP(cmd_keys_help)
	BAREBOX_CMD_COMPLETE(empty_complete)
BAREBOX_CMD_END
