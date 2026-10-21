/* SPDX-License-Identifier: GPL-2.0-only */
/* Host test: link libfdt, include its headers and patches/tb710fu/kernel.
 * Optional arguments are captured guest DTBs, read without modification.
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libfdt.h>
#include "gb-pci-compat.h"

static void exercise(const void *input, size_t size)
{
	unsigned char *copy = malloc(size);
	assert(copy);
	memcpy(copy, input, size);
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 1);
	size_t changes = 0;
	for (size_t i = 0; i < size; ++i) {
		if (copy[i] != ((const unsigned char *)input)[i]) {
			assert(copy[i] == 3 && ((const unsigned char *)input)[i] == 2);
			++changes;
		}
	}
	assert(changes == 1);
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 0);
	memcpy(copy, input, size);
	for (size_t length = 0; length < size; ++length)
		assert(gb_gunyah_normalize_pci_dtb(copy, length) == -EINVAL);
	int pci = fdt_path_offset(copy, "/pci"), len;
	fdt32_t *ranges = (fdt32_t *)fdt_getprop(copy, pci, "ranges", &len);
	assert(ranges && len == 56);
	ranges[2] = cpu_to_fdt32(0x2d000000);
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 0);
	memcpy(copy, input, size);
	ranges = (fdt32_t *)fdt_getprop(copy, pci, "ranges", &len);
	assert(ranges);
	ranges[7] = cpu_to_fdt32(0x02000000);
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 0);
	memcpy(copy, input, size);
	assert(!fdt_setprop_inplace_u32(copy, 0, "#address-cells", 1));
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 0);
	memcpy(copy, input, size);
	assert(!fdt_setprop_inplace_u32(copy, pci, "#address-cells", 2));
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 0);
	memcpy(copy, input, size);
	assert(!fdt_setprop_inplace(copy, pci, "compatible", "pci-host-ecam-generic", 21));
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == 0);
	memcpy(copy, input, size);
	fdt_set_magic(copy, 0);
	assert(gb_gunyah_normalize_pci_dtb(copy, size) == -EINVAL);
	free(copy);
}

int main(int argc, char **argv)
{
	char blob[4096];
	assert(!fdt_create_empty_tree(blob, sizeof(blob)));
	assert(!fdt_setprop_u32(blob, 0, "#address-cells", 2));
	int pci = fdt_add_subnode(blob, 0, "pci");
	assert(pci >= 0);
	assert(!fdt_setprop_string(blob, pci, "compatible", "pci-host-cam-generic"));
	assert(!fdt_setprop_u32(blob, pci, "#address-cells", 3));
	assert(!fdt_setprop_u32(blob, pci, "#size-cells", 2));
	uint32_t values[] = {0x02000000, 0, 0x2c000000, 0, 0x2c000000, 0,
		0x02000000, 0x43000000, 0, 0xe0600000, 0, 0xe0600000, 0xff, 0x1fa00000};
	for (size_t i = 0; i < 14; ++i)
		values[i] = cpu_to_fdt32(values[i]);
	assert(!fdt_setprop(blob, pci, "ranges", values, sizeof(values)));
	assert(!fdt_pack(blob));
	exercise(blob, fdt_totalsize(blob));
	char empty[256];
	assert(!fdt_create_empty_tree(empty, sizeof(empty)));
	assert(gb_gunyah_normalize_pci_dtb(empty, sizeof(empty)) == 0);
	for (int i = 1; i < argc; ++i) {
		FILE *file = fopen(argv[i], "rb");
		assert(file && !fseek(file, 0, SEEK_END));
		long size = ftell(file);
		assert(size > 0 && size <= 2 * 1024 * 1024 && !fseek(file, 0, SEEK_SET));
		void *data = malloc(size);
		assert(data && fread(data, 1, size, file) == (size_t)size);
		assert(!fclose(file));
		exercise(data, size);
		free(data);
	}
	printf("PCI range tests passed: synthetic + %d captured DTBs\n", argc - 1);
	return 0;
}
