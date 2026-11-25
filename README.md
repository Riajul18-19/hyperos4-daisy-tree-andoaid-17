# HyperOS 4 (Android 17) — Xiaomi Mi A2 Lite (`daisy`) Device & Kernel Tree

**Author & Lead Maintainer:** [Riajul (`Riajul18-19`)](https://github.com/Riajul18-19)  
**Target Hardware:** Xiaomi Mi A2 Lite (`daisy` / `daisy_sprout`, Qualcomm MSM8953 Snapdragon 625)  
**Kernel:** `Linux 4.9.337-Zero+` (`Ubuntu Clang 18.1.3`, `#7 SMP PREEMPT`, KernelSU + OrangeFox permanent recovery)  
**System Image:** Single-partition SAR `EROFS` (`-zlz4hc,12`), `2,354,712,576` bytes (`180.04 MB` free inside the `2,543,493,120`-byte `system_{a,b}` hardware slot)

---

## Hardware & Partition Specifications

| Component | Specification |
| :--- | :--- |
| **SoC** | Qualcomm MSM8953 Snapdragon 625 (14nm LPP, 8x ARM Cortex-A53 @ 2.0 GHz) |
| **GPU** | Adreno 506 (`kgsl-3d0`, `msm-adreno-tz`, HW GLES enabled: `persist.sys.force_sw_gles=0`) |
| **Display** | 5.84" IPS LCD `1080x2280` (`ro.sf.lcd_density=400`, MDSS DSI QRD-SKU3) |
| **Memory** | 3 GB / 4 GB LPDDR3 + `2048 MB` LZ4 zRAM (`swappiness=100`, `extm_on=0`) |
| **Partition Scheme** | Legacy A/B Non-Dynamic System-as-Root (`boot_{a,b}`, `system_{a,b}`, `vendor_{a,b}`) |
| **System Limit** | Exactly `2,543,493,120` bytes (`620,970` blocks @ `4096` B) — zero overflow |
| **Vendor HAL Base** | Android 9/10 QCOM MSM8953 vendor bridged via VNDK 29–34 & VINTF compatibility matrices |

---

## Repository Structure

```text
hyperos4-daisy-tree-andoaid-17/
├── AndroidProducts.mk              # Product lunch target (hyperos_daisy)
├── BoardConfig.mk                  # MSM8953 board config, EROFS limits, boot header & cmdline
├── device.mk                       # Device copy rules, init, VINTF & property layout
├── hyperos_daisy.mk                # Product identity & release-key overrides
│
├── kernel/
│   ├── README.md                   # Kernel 4.9.337 architecture, eBPF bridge & SDM625/Adreno 506 tuning
│   ├── boot/
│   │   └── boot_info.txt           # mkbootimg base (0x80008000), page size (2048), cmdline & header v0
│   ├── configs/
│   │   └── daisy_defconfig         # Authentic 5,081-line kernel config extracted from Image IKCFG_ST
│   ├── dts/
│   │   └── HARDWARE_DTB_AUDIT.md   # Decoded FDT nodes & panel bindings from dtb_1.dtb / dtb_2.dtb
│   └── prebuilt/
│       ├── Image.gz-dtb            # Prebuilt Linux 4.9.337-Zero+ compressed kernel + appended DTB
│       └── dtbs/                   # Primary & secondary QRD-SKU3 device tree blobs
│
├── ramdisk/
│   ├── README.md                   # First-stage & recovery ramdisk layout
│   ├── first_stage_ramdisk/
│   │   └── fstab.qcom              # A/B slot-select EROFS/EXT4/F2FS mount table
│   ├── prop.default                # Boot ramdisk properties
│   └── contexts/                   # Boot-time SELinux file, property, and service contexts
│
├── rootdir/
│   ├── bin/
│   │   └── daisy_init_defaults.sh  # Boot tuning (schedutil, cpu_boost, kgsl-3d0, VM, Device-MAC WiFi, clock heal)
│   └── etc/
│       ├── perfinit.conf           # 2 GB zRAM & dex2oat thread allocation (3/4/2 threads)
│       └── init/                   # Boot .rc manifests (init.rc, init.miui.ext.rc, netbpfload.rc, perfetto.rc)
│
├── configs/
│   ├── props/                      # system.prop, product.prop, system_ext.prop, mi_ext.prop
│   ├── sysconfig/                  # miui_whitelist.xml hidden-API exemptions
│   └── vintf/                      # System VINTF manifest & legacy HAL compatibility matrices (v5–v8, 202404–202604)
│
├── patches/
│   └── ARCHITECTURE_FIXES.md       # Framework, BPF ringbuf, SystemUI ABI, Launcher, Keymaster, Gralloc & WiFi fixes
│
├── flasher/
│   └── META-INF/                   # A/B active-slot TWRP/OrangeFox flasher scripts
│
├── scripts/
│   ├── build_release.py            # Reproducible EROFS image builder, DEX verifier, fsck/xattr auditor & ZIP packager
│   ├── run_elf_audit.py            # Transitive DT_NEEDED & VNDK symbol resolver
│   └── extract_kernel_config.py    # Helper to decompress Image.gz-dtb & dump IKCFG_ST .config + DTB bindings
│
└── docs/
    ├── PORT_BLUEPRINT.md           # Full SAR, Kernel, VINTF & hardware architecture blueprint
    ├── BUILD_REPORT.txt            # Verified fsck.erofs, dump.erofs & SHA-256 build report
    └── ELF_DEPENDENCY_AUDIT.txt    # Binary linkage & VNDK audit output
```

---

## Core Engineering Highlights

1. **Android 17 <-> Linux 4.9 eBPF & `system_server` Bring-Up**
   - Bridged Android 17 `ConnectivityService` / `LocalNetEventListener` (`BPF_MAP_TYPE_RINGBUF`, unsupported on Linux 4.9) cleanly across `services.jar`, `service-connectivity.jar`, `libservice-connectivity.so`, `init.rc`, and a static AArch64 `bpf_pin_aliases` binary performing `MS_BIND` mounts over `/apex/com.android.tethering` while leaving the Mainline APEX untouched on disk.
2. **Legacy Vendor (`msm8953` Android 9/10) HAL Compatibility**
   - Built fallback shims in `libui.so` (32/64-bit Gralloc Mapper 2.x/3.x), SurfaceFlinger `CONFIG_GROUP` handling, Keymaster 3.0 SPL patch alignment (`android.hardware.keymaster@3.0-impl-qti.so`), and VNDK 29–34 VINTF matrices.
3. **HyperOS 4 SystemUI, Lockscreen & Launcher Stability**
   - ABI-aligned Pandora `MiuiSystemUI.apk`, `MIUISystemUIPlugin.apk`, `MIUIAod.apk`, and `InCallUI.apk` with `miui-framework.jar` `ThemeValues` hidden-API unblock (`0x02 -> 0x00`) and full UTF-16 `string_ids` / Adler32 / SHA-1 DEX verification.
   - Tuned HWUI texture/layer caches for `1080x2280` 3 GB RAM devices, permanently disabled expensive full-screen SurfaceFlinger blur (`ro.miui.has_blur=0`), and kept Dynamic Island focused (`isNotificationPromotedOngoing` patched).
4. **Connectivity & Hardware Precision (`daisy`)**
   - Enforced device WiFi hardware MAC on Kernel 4.9 `wcnss`/`wlan0` via patched AOSP/Common WiFi Resource Overlays (`config_wifi_connected_mac_randomization_supported=false`), tuned `schedutil` + `cpu_boost` + `kgsl-3d0` `msm-adreno-tz`, and added boot-time auto-healing for lockscreen clock formatting.

---

## Building & Extracting

```bash
# 1. Re-extract the 5,081-line kernel .config and inspect FDT bindings
python3 scripts/extract_kernel_config.py \
  --kernel kernel/prebuilt/Image.gz-dtb \
  --dtb kernel/prebuilt/dtbs/dtb_1.dtb

# 2. Rebuild the verified EROFS system.img and flashable ZIP (from configured workspace)
python3 scripts/build_release.py

# 3. Flash system partition to active slot via fastboot
fastboot flash system_b system.img
fastboot reboot
```

---

## Maintainer & Credits

Designed, ported, engineered, and verified on hardware (`daisy`) by **Riajul** ([`@Riajul18-19`](https://github.com/Riajul18-19)).
