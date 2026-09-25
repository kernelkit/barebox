// SPDX-License-Identifier: GPL-2.0-only
/*
 * Make the EFI signature database available to signature verifiers:
 *
 * - The certificates and SHA256 digests in db are loaded into the "@efi"
 *   keyring, provided that the platform is in Secure Boot user mode, i.e.
 *   that db can only have been modified by the holder of a KEK.
 *
 * - The revoked certificates and digests in dbx are always added to the
 *   blacklist, since they can only ever make verification stricter.
 */

#define pr_fmt(fmt) "efi-db: " fmt

#include <common.h>
#include <init.h>
#include <efi/guid.h>
#include <efi/mode.h>
#include <efi/variable.h>
#include <linux/err.h>
#include <crypto/efi-siglist.h>
#include <crypto/public_key.h>

#define EFI_DB_KEYRING "@efi"

static bool efi_db_var_is(const char *name, u8 expected)
{
	u8 *val;
	int size;
	bool ret;

	val = efi_get_global_var((char *)name, &size);
	if (IS_ERR(val))
		return false;

	ret = size == 1 && *val == expected;
	free(val);
	return ret;
}

static bool efi_db_trusted(void)
{
	bool secure = efi_db_var_is("SecureBoot", 1) &&
		      efi_db_var_is("SetupMode", 0);

	if (secure)
		return true;

	if (IS_ENABLED(CONFIG_CRYPTO_EFI_DB_INSECURE)) {
		pr_warn("Secure Boot is not enforced, trusting db anyway\n");
		return true;
	}

	pr_warn("Secure Boot is not enforced, not trusting db\n");
	return false;
}

static int efi_db_load(const char *name,
		       int (*load)(struct keyring *, const void *, size_t),
		       struct keyring *kr)
{
	void *data;
	int size, ret;

	data = efi_get_variable((char *)name,
				(efi_guid_t *)&efi_guid_image_security_database,
				&size);
	if (IS_ERR(data)) {
		ret = PTR_ERR(data);
		/* An empty database is perfectly valid */
		if (ret != -ENODEV)
			pr_warn("Unable to read %s: %pe\n", name, data);
		return ret;
	}

	ret = load(kr, data, size);
	if (ret)
		pr_warn("Unable to parse %s: %pe\n", name, ERR_PTR(ret));

	free(data);
	return ret;
}

static int efi_db_init(void)
{
	struct keyring *kr, *bl;

	if (!efi_is_payload())
		return 0;

	bl = keyring_blacklist();
	if (bl)
		efi_db_load("dbx", efi_siglist_load_dbx, bl);

	kr = keyring_create(EFI_DB_KEYRING);
	if (IS_ERR(kr))
		return PTR_ERR(kr);

	if (efi_db_trusted())
		efi_db_load("db", efi_siglist_load_db, kr);

	return 0;
}
late_initcall(efi_db_init);
