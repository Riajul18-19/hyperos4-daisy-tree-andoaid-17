# Xiaomi Mi A2 Lite (`daisy`) — HyperOS 4 Architecture Blueprint

**Author & Maintainer:** Riajul (`Riajul18-19`)

## 1. Hardware & Partition Architecture Overview
- **Device:** Xiaomi Mi A2 Lite (`daisy` / `daisy_sprout`)
- **Platform / SoC:** Qualcomm MSM8953 Snapdragon 625 (14nm, 8x ARM Cortex-A53 @ 2.0 GHz, Adreno 506)
- **Partition Scheme:** A/B non-dynamic legacy partitions (No `super` dynamic partition)
  - System slot nodes: `/dev/block/bootdevice/by-name/system_a`, `/dev/block/bootdevice/by-name/system_b`
  - Vendor slot nodes: `/dev/block/bootdevice/by-name/vendor_a`, `/dev/block/bootdevice/by-name/vendor_b`
  - Boot slot nodes: `/dev/block/bootdevice/by-name/boot_a`, `/dev/block/bootdevice/by-name/boot_b`
- **Exact System Partition Limit:** `2,543,493,120` bytes (`620,970` blocks @ `4,096` bytes)
- **Filesystem:** Read-only `EROFS` (`0xE0F5E1E2`) with `LZ4HC` level 12 compression (`-zlz4hc,12`)

## 2. Kernel & First-Stage Ramdisk Layout
- **Kernel:** `Linux 4.9.337-Zero+` (`PREEMPT SMP`, `Ubuntu Clang 18.1.3`) with built-in KernelSU and permanent OrangeFox recovery
- **Page Size / Base / Header:** `2048` bytes / `0x80008000` / Header v0
- **First-Stage Mount (`ramdisk/first_stage_ramdisk/fstab.qcom`):** Mounts `system` (`erofs`, `ro`, `slotselect`), `vendor` (`ext4`, `ro`, `slotselect`), `userdata` (`f2fs`/`ext4`, `fileencryption=ice`, `quota`), `persist`, `dsp`, and `firmware_mnt`

## 3. Single-System SAR (System-as-Root) Partition Merge
Because `daisy` has no dynamic partitions for `product`, `system_ext`, or `mi_ext`, those directories are baked directly into the root of `system.img`:
- `/system`, `/product`, `/system_ext`, `/mi_ext`
- Root symlinks: `/bin -> /system/bin`, `/etc -> /system/etc`, `/init -> /system/bin/init`, `/sdcard -> /storage/self/primary`, `/firmware -> /vendor/firmware_mnt`, `/persist -> /mnt/vendor/persist`, `/dsp -> /vendor/dsp`
- System internal symlinks: `/system/product -> /product`, `/system/system_ext -> /system_ext`, `/system/vendor -> /vendor`, `/system/media -> /product/media`

## 4. VNDK, VINTF & Legacy MSM8953 Vendor Bridge
- Bridges Xiaomi stock Android 9/10 `vendor.img` HALs (`Audio`, `Camera`, `DRM`, `Bluetooth`, `Lights`, `Sensors`, `RIL`, `Fingerprint`, `Keymaster 3.0`) up to Android 17 via `libvndksupport.so`, `libcodec2_vndk.so`, 32/64-bit `libui.so` Gralloc 2.x/3.x shims, and `configs/vintf/compatibility_matrix.*.xml` (levels 29–34 and 202404–202604).

## 5. Production Display & SoC Alignment
- Panel: `1080x2280`, `ro.sf.lcd_density=400`, `persist.sys.force_sw_gles=0`, `debug.sf.disable_backpressure=0`
- SoC Identification: `ro.soc.model=Snapdragon 625`, `ro.product.mod_device=daisy`, `dalvik.vm.isa.arm64.variant=cortex-a53`
- Hardware GLES / Blur Policy: `ro.miui.has_blur=0`, `ro.miui.blur.level=0`, `ro.surface_flinger.supports_background_blur=0`
