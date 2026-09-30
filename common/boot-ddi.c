// SPDX-License-Identifier: GPL-2.0-only
/*
 * Boot entries for Discoverable Disk Images (DDIs)
 *
 * A DDI, as described by the UAPI Group's Discoverable Partitions
 * Specification, holds a root filesystem protected by dm-verity, along
 * with the verity hash tree, and a signature of the verity root hash:
 *
 * https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
 *
 * Disks holding such a triplet of partitions for the native architecture
 * are offered as boot entries. When booted, the root hash signature is
 * verified against the keyring named by global.ddi.keyring, the verity
 * device is set up and mounted, and the Boot Loader Specification entries
 * found in the root filesystem are tried in order.
 *
 * If global.ddi.require_trust is cleared, DDIs whose signature can not be
 * verified are booted anyway, using the root hash as is.
 *
 * The verified root hash is handed to Linux using the kernel command line
 * parameters understood by systemd-veritysetup-generator.
 */

#define pr_fmt(fmt) "ddi: " fmt

#include <common.h>
#include <boot.h>
#include <bootscan.h>
#include <device-mapper.h>
#include <driver.h>
#include <fs.h>
#include <globalvar.h>
#include <init.h>
#include <libfile.h>
#include <magicvar.h>
#include <spec/dps.h>
#include <linux/err.h>
#include <crypto/public_key.h>
#include <crypto/verity-sig.h>
#include <crypto/x509.h>

/* Named like systemd-veritysetup-generator does it */
#define DDI_DM_NAME "root"

static char *ddi_keyring;
static int require_trust = 1;

struct ddi_entry {
	struct bootentry entry;

	struct cdev *disk;
	struct cdev *root;
	struct cdev *verity;
	struct cdev *sig;
};

/*
 * ddi_root_hash_untrusted - fall back to the unverified root hash
 *
 * Only used when trust is not required, in which case the root hash is
 * taken from the signature document as is. dm-verity still verifies the
 * root filesystem against it, which guards against corruption, but not
 * against tampering.
 */
static char *ddi_root_hash_untrusted(struct ddi_entry *entry,
				     const void *buf, size_t len)
{
	struct verity_sig sig;
	char *root_hash;
	int ret;

	ret = verity_sig_parse(buf, len, &sig);
	if (ret) {
		pr_err("%s: invalid root hash signature: %pe\n",
		       entry->disk->name, ERR_PTR(ret));
		return ERR_PTR(ret);
	}

	pr_warn("%s: booting with untrusted root hash\n", entry->disk->name);

	root_hash = sig.root_hash;
	sig.root_hash = NULL;
	verity_sig_free(&sig);
	return root_hash;
}

static char *ddi_verify(struct ddi_entry *entry, int verbose)
{
	const struct public_key *key = NULL;
	const struct keyring *kr;
	char *path, *root_hash = NULL;
	size_t len;
	void *buf;
	int ret;

	path = xasprintf("/dev/%s", entry->sig->name);
	buf = read_file(path, &len);
	free(path);
	if (!buf)
		return ERR_PTR(-errno);

	kr = keyring_find(ddi_keyring);
	if (!kr) {
		pr_err("%s: no such keyring\n", ddi_keyring);
		ret = -ENOKEY;
		goto out;
	}

	ret = verity_sig_verify(buf, len, kr, &root_hash, &key);
	if (ret) {
		pr_err("%s: root hash signature verification failed: %pe\n",
		       entry->disk->name, ERR_PTR(ret));
		goto out;
	}

	if (verbose) {
		if (key && key->cert)
			pr_info("%s: root hash vouched for by \"%s\"\n",
				entry->disk->name, key->cert->subject);
		else
			pr_info("%s: root hash vouched for by %s\n",
				entry->disk->name, key ? "key" : "its digest");
	}
out:
	if (ret)
		root_hash = require_trust ? ERR_PTR(ret) :
			ddi_root_hash_untrusted(entry, buf, len);

	free(buf);
	return root_hash;
}

static struct dm_device *ddi_open(struct ddi_entry *entry,
				  const char *root_hash)
{
	struct dm_device *dm;
	char *data, *hash, *table;

	dm = dm_find_by_name(DDI_DM_NAME);
	if (!IS_ERR_OR_NULL(dm)) {
		pr_err("A device named \"%s\" already exists\n", DDI_DM_NAME);
		return ERR_PTR(-EBUSY);
	}

	data = xasprintf("/dev/%s", entry->root->name);
	hash = xasprintf("/dev/%s", entry->verity->name);

	table = dm_verity_config_from_sb(data, hash, root_hash);
	free(data);
	free(hash);
	if (IS_ERR(table))
		return ERR_CAST(table);

	dm = dm_create(DDI_DM_NAME, table);
	free(table);
	return dm;
}

static int ddi_boot_entries(struct ddi_entry *entry, const char *rootpath,
			    const char *bootargs, int verbose, int dryrun)
{
	struct bootentry_provider *blspec;
	struct bootentries *entries;
	struct bootentry *be;
	int ret;

	blspec = get_bootentry_provider("blspec");
	if (!blspec) {
		pr_err("Boot Loader Specification support is not available\n");
		return -ENOSYS;
	}

	entries = bootentries_alloc();

	ret = blspec->generate(entries, rootpath);
	if (ret <= 0) {
		pr_err("%s: no boot entries found\n", entry->disk->name);
		ret = ret ?: -ENOENT;
		goto out;
	}

	bootentries_for_each_entry(entries, be) {
		/* boot_entry() clears dynamic bootargs after each attempt */
		globalvar_add_simple("linux.bootargs.dyn.ddi", bootargs);

		ret = boot_entry(be, verbose, dryrun);
		if (!ret)
			break;
	}
out:
	bootentries_free(entries);
	return ret;
}

/*
 * ddi_boot - verify, open and boot a DDI
 *
 * On success this function does not return, except for dry runs. On
 * failure, all traces of the attempt are removed.
 */
static int ddi_boot(struct bootentry *be, int verbose, int dryrun)
{
	struct ddi_entry *entry = container_of(be, struct ddi_entry, entry);
	struct dm_device *dm;
	const char *rootpath;
	char *root_hash, *bootargs;
	struct cdev *cdev;
	int ret;

	root_hash = ddi_verify(entry, verbose);
	if (IS_ERR(root_hash))
		return PTR_ERR(root_hash);

	dm = ddi_open(entry, root_hash);
	if (IS_ERR(dm)) {
		ret = PTR_ERR(dm);
		pr_err("%s: failed to open verity device: %pe\n",
		       entry->disk->name, dm);
		goto out_free;
	}

	cdev = cdev_by_name(DDI_DM_NAME);
	if (!cdev) {
		ret = -ENODEV;
		goto out_close;
	}

	if (require_trust && !cdev_is_trusted(cdev)) {
		ret = -EKEYREJECTED;
		goto out_close;
	}

	rootpath = cdev_mount(cdev);
	if (IS_ERR(rootpath)) {
		ret = PTR_ERR(rootpath);
		pr_err("%s: failed to mount root filesystem: %pe\n",
		       entry->disk->name, rootpath);
		goto out_close;
	}

	bootargs = xasprintf("roothash=%s ", root_hash);

	if (verbose)
		pr_info("Adding \"%s\" to Kernel commandline\n", bootargs);

	ret = ddi_boot_entries(entry, rootpath, bootargs, verbose, dryrun);

	free(bootargs);
	umount(rootpath);
out_close:
	dm_destroy(dm);
out_free:
	free(root_hash);
	return ret;
}

static void ddi_entry_free(struct bootentry *be)
{
	/* The title, description and path are freed by bootentries_free() */
	free(container_of(be, struct ddi_entry, entry));
}

static struct cdev *ddi_find_part(struct cdev *disk, const guid_t *type)
{
	struct cdev *part;

	part = cdev_find_child_by_gpt_typeuuid(disk, type);

	return IS_ERR(part) ? NULL : part;
}

/*
 * ddi_scan_disk - scan a disk for a DDI
 *
 * Nothing is verified at this point, so that listing boot entries stays
 * cheap and free of side effects.
 */
static int ddi_scan_disk(struct bootscanner *scanner,
			 struct bootentries *bootentries, struct cdev *disk)
{
	struct ddi_entry *entry;
	struct cdev *root, *verity, *sig;

	if (!cdev_is_gpt_partitioned(disk))
		return 0;

	root = ddi_find_part(disk, &SD_GPT_ROOT_NATIVE);
	verity = ddi_find_part(disk, &SD_GPT_ROOT_NATIVE_VERITY);
	sig = ddi_find_part(disk, &SD_GPT_ROOT_NATIVE_VERITY_SIG);
	if (!root || !verity || !sig)
		return 0;

	pr_debug("%s: found DDI\n", disk->name);

	entry = xzalloc(sizeof(*entry));
	entry->disk = disk;
	entry->root = root;
	entry->verity = verity;
	entry->sig = sig;

	entry->entry.title = xasprintf("DDI on %s", disk->name);
	entry->entry.description =
		xasprintf("DDI, root: %s verity: %s signature: %s",
			  root->name, verity->name, sig->name);
	entry->entry.path = xstrdup(disk->name);
	entry->entry.me.type = MENU_ENTRY_NORMAL;
	entry->entry.boot = ddi_boot;
	entry->entry.release = ddi_entry_free;

	bootentries_add_entry(bootentries, &entry->entry);
	return 1;
}

static struct bootscanner ddi_scanner = {
	.name		= "ddi",
	.scan_disk	= ddi_scan_disk,
};

static int ddi_bootentry_generate(struct bootentries *bootentries,
				  const char *name)
{
	return bootentry_scan_generate(&ddi_scanner, bootentries, name);
}

static struct bootentry_provider ddi_bootentry_provider = {
	.name = "ddi",
	.generate = ddi_bootentry_generate,
	/* A DDI is booted as such, rather than as a plain disk */
	.priority = 10,
};

static int ddi_init(void)
{
	ddi_keyring = xstrdup("os");
	globalvar_add_simple_string("ddi.keyring", &ddi_keyring);
	globalvar_add_simple_bool("ddi.require_trust", &require_trust);

	return bootentry_register_provider(&ddi_bootentry_provider);
}
device_initcall(ddi_init);

BAREBOX_MAGICVAR(global.ddi.keyring,
		 "Keyring used to verify the root hash signatures of DDIs");
BAREBOX_MAGICVAR(global.ddi.require_trust,
		 "Only boot DDIs whose root hash signature can be verified (default: 1)");
