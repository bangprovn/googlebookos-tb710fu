/* SPDX-License-Identifier: GPL-2.0-only */
/* Device-scoped compatibility for the retained TB710FU Android pVM firmware.
 * Include libfdt and errno/string declarations before this pure transformer.
 * Return 1 when changed, 0 for another/already-normalized layout, or -EINVAL.
 */
#ifndef GB_GUNYAH_PCI_COMPAT_H
#define GB_GUNYAH_PCI_COMPAT_H

static inline int gb_gunyah_normalize_pci_dtb(void *blob, size_t available)
{
	const fdt32_t *ranges, *cells;
	fdt32_t replacement[14];
	int pci, len;

	if (available < sizeof(struct fdt_header) || fdt_check_header(blob) ||
	    fdt_version(blob) != 17 || fdt_totalsize(blob) > available)
		return -EINVAL;
	pci = fdt_path_offset(blob, "/pci");
	if (pci < 0 || fdt_node_check_compatible(blob, pci, "pci-host-cam-generic"))
		return 0;
	cells = fdt_getprop(blob, 0, "#address-cells", &len);
	if (!cells || len != 4 || fdt32_to_cpu(*cells) != 2)
		return 0;
	cells = fdt_getprop(blob, pci, "#address-cells", &len);
	if (!cells || len != 4 || fdt32_to_cpu(*cells) != 3)
		return 0;
	cells = fdt_getprop(blob, pci, "#size-cells", &len);
	if (!cells || len != 4 || fdt32_to_cpu(*cells) != 2)
		return 0;
	ranges = fdt_getprop(blob, pci, "ranges", &len);
	if (!ranges || len != sizeof(replacement) ||
	    fdt32_to_cpu(ranges[0]) != 0x02000000 ||
	    fdt32_to_cpu(ranges[1]) != 0 ||
	    fdt32_to_cpu(ranges[2]) != 0x2c000000 ||
	    fdt32_to_cpu(ranges[3]) != 0 ||
	    fdt32_to_cpu(ranges[4]) != 0x2c000000 ||
	    fdt32_to_cpu(ranges[5]) != 0 ||
	    fdt32_to_cpu(ranges[6]) != 0x02000000 ||
	    (fdt32_to_cpu(ranges[7]) & 0x03000000) != 0x03000000)
		return 0;

	/* A 64-bit PCI memory window can reside below 4 GiB. Preserve every
	 * address, size, prefetch flag, interrupt and unrelated byte. The retained
	 * pvmfw still validates the tree and verifies kernel/ramdisk signatures.
	 */
	memcpy(replacement, ranges, sizeof(replacement));
	replacement[0] = cpu_to_fdt32(0x03000000);
	if (fdt_setprop_inplace(blob, pci, "ranges", replacement, sizeof(replacement)))
		return -EINVAL;
	return 1;
}

#endif
