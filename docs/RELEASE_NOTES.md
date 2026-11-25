# HyperOS 4 (Android 17) — Xiaomi Mi A2 Lite (`daisy`)

**Maintainer:** Riajul (`Riajul18-19`)  
**Kernel:** Linux `4.9.337-Zero+` (KernelSU + OrangeFox built-in)  
**Target:** Xiaomi Mi A2 Lite (`daisy` / MSM8953 Snapdragon 625)

Clean, daily-driver tuned HyperOS 4 (Android 17) build for Xiaomi Mi A2 Lite (`daisy`). Built around native `1080x2280` (`400 dpi`) HW GLES, `EROFS LZ4HC`, legacy MSM8953 HAL & eBPF bridges, ABI-matched SystemUI/Volume/Control Center, working WLAN dialog/details with Device-MAC WiFi, customizable lockscreen clock (`:`), fast first-boot Setup (`pm.dexopt.first-boot=verify` + background `dex2oat` offloaded to cores `4-7`), and `2 GB` LZ4 zRAM.

---

## Downloads
- **OrangeFox / Boot Image:** `orangefox.img` (`40,452,096` bytes, `SHA-256: 42759758f7e246c28744c202a82128b6630cb887eb0abace5bbf51ca2d8e3c86`)
- **ROM Package:** `HyperOS-4-Android17-daisy-Release-Final.zip` (`3,216,430,502` bytes, `SHA-256: 42bb6d49b6608dd60ff3f1509c15a6078235ef89e825e6bcf263b54f07fead6d`)

---

## Clean Installation Guide

Reboot your phone into **Fastboot Mode** (`Vol Down + Power`) and run these commands in order:

```bash
# 1. Wipe userdata cleanly before flashing recovery & ROM
fastboot -w

# 2. Flash OrangeFox recovery/boot to both A/B slots
fastboot flash boot_a orangefox.img
fastboot flash boot_b orangefox.img

# 3. Reboot straight into OrangeFox Recovery
fastboot reboot
```

Once inside **OrangeFox Recovery**:

4. Tap the **Wipe (Trash icon)** → **Format Data** → type `yes` and confirm.
5. Open **Menu / Settings** in OrangeFox → turn on **ADB Sideload**, then run on your PC:
   ```bash
   adb sideload HyperOS-4-Android17-daisy-Release-Final.zip
   ```
6. Reboot to System. First boot takes ~60–90 seconds.

---

## What's Fixed in This Release
- Fixed Settings WLAN crash (`WifiConfigController2` null `Spinner.setSelection`) when tapping WiFi networks to enter a password.
- Fixed slow/laggy first-boot setup (`pm.dexopt.first-boot=verify`, `dex2oat` offloaded to cores `4-7`, native `on boot` sysfs CPU/GPU/eMMC/VM writes).
- Fixed Volume UI, Control Center, Dynamic Island notification trigger, Lockscreen clock (`:`) + Editor, Wallpaper picker, WiFi Device-MAC, and Call UI stability.
