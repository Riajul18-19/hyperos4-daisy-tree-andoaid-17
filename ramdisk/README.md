# Xiaomi Mi A2 Lite (`daisy`) — Ramdisk Layout

**Maintainer:** Riajul (`Riajul18-19`)

Because `daisy` uses A/B System-as-Root (`BOARD_USES_RECOVERY_AS_BOOT=true`), the boot ramdisk hosts:
- **`first_stage_ramdisk/fstab.qcom`**: Slot-selected read-only `EROFS` `/system`, `EXT4` `/vendor`, `F2FS`/`EXT4` `/data` with inline-crypto (`fileencryption=ice`), `/mnt/vendor/persist`, `/vendor/dsp`, `/vendor/firmware_mnt`, `/misc`, `/frp`, SDHCI, and USB OTG mounts.
- **`prop.default`**: Verified first-stage boot properties.
- **`contexts/`**: Boot SELinux `plat_*`, `vendor_*`, `product_*`, `system_ext_*`, and `odm_*` file/property/service context files.

*(Prebuilt ELF recovery binaries inside the packed `boot.img` ramdisk are omitted from git source control to keep the repository clean; use `META-INF` or the release boot image for flashing.)*
