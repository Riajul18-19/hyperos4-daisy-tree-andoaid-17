# HyperOS 4 (Android 17) — Xiaomi Mi A2 Lite (`daisy`)

**Maintainer:** Riajul (`Riajul18-19`)  
**Kernel:** Linux `4.9.337-Zero+` (KernelSU + OrangeFox built-in)  
**Target:** Xiaomi Mi A2 Lite (`daisy` / MSM8953 Snapdragon 625)

Built and tuned for Xiaomi Mi A2 Lite (`daisy`) with EROFS LZ4HC compression, legacy MSM8953 vendor HAL bridges, Android 17 eBPF compatibility, ABI-aligned SystemUI/Volume/Control Center/Launcher, customizable lockscreen clock (`:`), Device-MAC WiFi, 2 GB zRAM, and native `1080x2280` (`400 dpi`) HW GLES rendering.

---

## Downloads
- **ROM ZIP:** `HyperOS-4-Android17-daisy-Release-Final.zip` (`3,217,253,798` bytes, `SHA-256: 7f8ea1a3346d171b48f9274306afd91f843fd17fc995e760c2a22cfdfd8ddb37`)
- **Recovery / Boot Image:** `boot_orangefox.img` (`40,452,096` bytes, `SHA-256: 42759758f7e246c28744c202a82128b6630cb887eb0abace5bbf51ca2d8e3c86`)

---

## How to Install

### 1. Flash OrangeFox Recovery (First-Time Setup)
Reboot to bootloader (`Vol Down + Power`) and flash OrangeFox to your active slot:
```bash
fastboot getvar current-slot
fastboot flash boot_a boot_orangefox.img   # use boot_b if current-slot is b
fastboot reboot recovery
```

### 2. Clean Flash HyperOS 4
1. In **OrangeFox Recovery**, open **Wipe → Format Data** and confirm `yes` (only needed when switching from another ROM; skip if updating over an earlier HyperOS 4 build).
2. Flash `HyperOS-4-Android17-daisy-Release-Final.zip` from storage — or use **ADB Sideload**:
   ```bash
   adb sideload HyperOS-4-Android17-daisy-Release-Final.zip
   ```
   *(The installer writes `splash`, `boot`, `vendor`, and `system` to your active slot with permanent OrangeFox + KernelSU intact.)*
3. Reboot to System (first boot takes ~60–90 seconds).
