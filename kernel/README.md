# Xiaomi Mi A2 Lite (`daisy`) — Kernel `4.9.337-Zero+` Architecture & Engineering Guide

**Maintainer:** Riajul (`Riajul18-19`)  
**Kernel Banner:** `Linux version 4.9.337-Zero+ (zero@zero) (Ubuntu clang version 18.1.3 (1ubuntu1)) #7 SMP PREEMPT Fri Oct 23 16:30:14 UTC 2026`  
**Boot Base / Page Size:** `0x80008000` / `2048` bytes / `BOARD_HEADER_VERSION=0`

---

## 1. Kernel Binary Layout & `IKCFG_ST` Config

The prebuilt boot kernel at `kernel/prebuilt/Image.gz-dtb` (`13,132,530` bytes) is a gzip-compressed AArch64 Linux `Image` (`38,154,264` bytes uncompressed) with concatenated MSM8953 QRD-SKU3 device tree blobs (`567,647` bytes total appended DTB payload; split references stored in `kernel/prebuilt/dtbs/dtb_1.dtb` and `dtb_2.dtb`).

Kernel configuration introspection (`CONFIG_IKCONFIG=y`) is embedded directly inside the `Image` payload under the `IKCFG_ST` gzip stream, from which all **5,081** configuration symbols in `kernel/configs/daisy_defconfig` were extracted.

You can re-verify or re-extract the config at any time using:
```bash
python3 scripts/extract_kernel_config.py --kernel kernel/prebuilt/Image.gz-dtb --out kernel/configs/daisy_defconfig
```

---

## 2. Boot Command Line

```text
androidboot.hardware=qcom
msm_rtb.filter=0x237
ehci-hcd.park=3
lpm_levels.sleep_disabled=1
androidboot.bootdevice=7824900.sdhci
earlycon=msm_hsl_uart,0x78af000
loop.max_part=7
androidboot.boot_devices=soc/7824900.sdhci
androidboot.selinux=permissive
printk.devkmsg=on
```

---

## 3. Running Android 17 User-Space on Linux 4.9

Bringing up HyperOS 4 (Android 17) on Kernel `4.9.337` requires handling strict kernel/user-space ABI boundaries:

1. **No BPF Ring Buffers (`BPF_MAP_TYPE_RINGBUF`, Linux 5.8+)**:
   - Android 17 `ConnectivityService` instantiates `LocalNetEventListener`, whose native library `libservice-connectivity.so` aborts if `/sys/fs/bpf/netd_shared/map_netd_local_net_note_op_ringbuf` returns `ENOENT`.
   - Handled cleanly in user-space without degrading TCP/IP or DNS routing (`services.jar` redirection -> `service-connectivity.jar` null return -> `libservice-connectivity.so` abort neutralization -> `bpf_pin_aliases` `MS_BIND` mount).
2. **Legacy cgroup & Task Boost Semantics**:
   - Disabled `iorapd` (`init.launch_boost.rc`, `persist.sys.stability.PrereadEnable=false`) to prevent unnecessary I/O stalls on 4.9.
   - Mapped cpusets specifically for 8x Cortex-A53 (`background=0-1`, `system-background=0-2`, `top-app=0-7`).
3. **14nm Snapdragon 625 & Adreno 506 Runtime Tuning (`daisy_init_defaults.sh` & `perfinit.conf`)**:
   - **CPU Governor (`schedutil`)**: `up_rate_limit_us=500`, `down_rate_limit_us=20000`, `hispeed_freq=1689600`, `hispeed_load=80`, `iowait_boost_enable=1`.
   - **Input Boost (`cpu_boost`)**: `input_boost_freq=0:1401600 1:1401600 2:1401600 3:1401600 4:0 5:0 6:0 7:0`, `input_boost_ms=80`, `sched_boost_on_input=1`.
   - **GPU (`kgsl-3d0`)**: `msm-adreno-tz`, `polling_interval=10`, `idle_timer=70`, `bus_split=1`, `hwcg=1`, `preemption=1`, `max_pwrlevel=0`, `min_pwrlevel=7`, `default_pwrlevel=6`.
   - **Memory / zRAM**: `2048 MB` LZ4 `zram0`, `vm.swappiness=100`, `vm.extra_free_kbytes=24300`, `extm_on=0`, and bounded `dex2oat` thread pool (`3`/`4`/`2`) to prevent thermal throttling or LMKD thrashing on 3 GB SKUs.
4. **Integrated Kernel Features**:
   - Built-in **KernelSU** support and permanent **OrangeFox Recovery** inside boot ramdisk.
