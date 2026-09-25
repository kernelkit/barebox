/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __CRYPTO_EFI_SIGLIST_H
#define __CRYPTO_EFI_SIGLIST_H

#include <linux/types.h>

struct keyring;

int efi_siglist_load_db(struct keyring *kr, const void *data, size_t size);
int efi_siglist_load_dbx(struct keyring *blacklist, const void *data,
			 size_t size);

#endif /* __CRYPTO_EFI_SIGLIST_H */
