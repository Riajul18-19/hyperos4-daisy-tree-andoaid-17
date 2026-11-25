# HyperOS 4 (Android 17) Port Architecture & Engineering Fixes (`daisy`)

**Author:** Riajul (`Riajul18-19`)

All runtime fixes below are implemented reproducibly in `scripts/build_release.py` and `rootdir/bin/daisy_init_defaults.sh`, with full ELF/DEX/SELinux post-build validation.

---

## 1. Kernel 4.9 <-> Android 17 Framework & Native Bridges
- **Connectivity BPF RingBuffer Neutralization**:
  - `services.jar` (`classes.dex`): redirects `service-connectivity.jar` lookup to `/system///////////////////framework/service-connectivity.jar` (exact 60-char preserve-order path).
  - `service-connectivity.jar` (`classes.dex`): patches `ConnectivityService$Dependencies.getLocalNetEventListener` and `LocalNetEventListener$Dependencies.getFileDescriptor` to return `null`.
  - `libservice-connectivity.so`: patches `nativeGetLocalNetAccessRingbufFd` (`0xdfb0`) to return `0` and NOPs `abort()` (`0xf4bc`) inside `LocalNetEventHandler::GetRingbuf()`.
  - `bpf_pin_aliases` (static AArch64 binary) & `init.rc`: pins BPF map aliases and performs `mount(..., MS_BIND)` over `/apex/com.android.tethering` while keeping the Mainline APEX untouched.
- **Display Backlight & SurfaceFlinger (MSM8953 IPS LCD)**:
  - `services.jar` (`classes2.dex`): neutralizes fatal `constrainNitsAndBacklightArrays` throw branches, clamps `LightsService.setBrightness` to legacy 8-bit `[12, 255]`, and enforces native `1080x2280` @ `400 dpi`.
  - `libui.so` (32-bit & 64-bit) & `surfaceflinger`: adds Gralloc Mapper 2.x/3.x fallback paths and `CONFIG_GROUP (7)` interception.
  - Cleared flagship AMOLED `displayconfig` XML overrides from `product/etc/displayconfig/`.
- **Keymaster 3.0 Vendor Alignment**:
  - Aligned `android.hardware.keymaster@3.0-impl-qti.so` SPL checks with `daisy` bootloader/TrustZone.

## 2. HyperOS 4 SystemUI, Plugin, Launcher & Lockscreen Stack
- **ABI-Matched SystemUI + Plugin Stack**:
  - Paired Pandora `MiuiSystemUI.apk` with matching Pandora `MIUISystemUIPlugin.apk` (`VolumeDialogController.setStreamVolume(IIZ)V` and virtual `PluginDependency.get`) to eliminate volume slider `NoSuchMethodError` and Control Center `IncompatibleClassChangeError`.
  - Patched `PromotedNotificationParamUtils.isNotificationPromotedOngoing` (`classes2.dex`) so ordinary notifications do not force Dynamic Island expansion while preserving active media/timer/call island views.
- **MiuiHome & Gesture Navigation**:
  - Unblocked `Lmiui/content/res/ThemeValues;` hidden-API flags (`0x02 -> 0x00` across 22 members at DEX offset `0x71e30b`) in `miui-framework.jar` and whitelisted `com.miui.home`, `miui.systemui.plugin`, `com.miui.miwallpaper`, `com.miui.securitycenter`, and `com.miui.aod` in `miui_whitelist.xml`.
  - Restored verifier-clean `RecentsAnimationListenerImpl.finishController` bytecode in `MiuiHome.apk` (`classes2.dex`), enabled gesture navigation via `Miui-WindowManager-Shell.jar`, and scaled animation flags (`isHighAnimationRate=False`) cleanly for Adreno 506.
- **Lockscreen Clock Editor (`MIUIAod.apk`) & Auto-Heal**:
  - Integrated Pandora `MIUIAod.apk` (`com.android.systemui.action.KEYGUARD_EDITOR`) while disabling AOD on IPS LCD (`doze_always_on=0`, `aod_mode=0`).
  - Added one-time legacy `constant_template_editor_info` auto-heal in `daisy_init_defaults.sh` (`"fontStyle":0` + `"isColonShow":false` + `"isDoubleRow":false` -> `"fontStyle":21,"isColonShow":true,"clockWeight":420`) while keeping user customizations intact.
- **Wallpaper & Telephony**:
  - Restored `GoogleWallpaper.apk` (`android.intent.action.SET_WALLPAPER` resolver) and fitted the default wallpaper cleanly to `1080x2280`.
  - Paired authentic Xiaomi-signed Pandora `InCallUI.apk` (`v40.01.63`).

## 3. Settings WLAN & First-Boot Setup Optimizations
- **WLAN Bottom-Sheet Crash (`Settings.apk`)**:
  - In `classes4.dex` (`WifiConfigController2.initWifiConfigController2`), `mPrivacySettingsSpinner` is left `null` when `config_wifi_connected_mac_randomization_supported=false`. Guarded `+0x0882` (`0x2ad526`, 10 bytes) in-place to eliminate `NullPointerException` on `Spinner.setSelection(int)` when connecting to new WiFi networks, preserving original `APK Sig Block 42` Xiaomi signatures.
- **WiFi Hardware MAC Enforcement (Kernel 4.9 `wcnss` / `wlan0`)**:
  - Patched `config_wifi_connected_mac_randomization_supported` to `false` (`0xffffffff -> 0x00000000`) across `AospWifiResOverlay.apk`, `AospWifiResOverlay_mainline.apk`, `WifiResCommon_Sys.apk`, and `WifiResCommonMainline_Sys.apk`.
  - Enforced `wifi_connected_mac_randomization_enabled=0` and `WifiConfigStore.xml` `MacRandomizationSetting` sanitization at boot so `wlan0` binds using Daisy's genuine Qualcomm hardware MAC.
- **Native First-Boot Setup Optimization**:
  - Switched `pm.dexopt.first-boot=verify`, `pm.dexopt.boot-after-ota=verify`, and offloaded `dalvik.vm.dex2oat-cpu-set=4,5,6,7` so UI/SetupWizard cores `0-3` remain responsive.
  - Applied native `init.rc` `on boot` sysfs writes for `mmcblk0`, VM/zRAM, cpusets, `cpu_boost`, and `kgsl-3d0` before first frame, and guarded one-time `pm grant`/`appops` calls behind `persist.daisy.perms_v26`.

## 4. Verification Discipline
- Every patched APK keeps original signing intact where required and passes `zipfile.ZipFile(apk).testzip() is None`.
- Every modified `.dex` file undergoes full header, SHA-1, Adler32, bounds, and strict UTF-16 `string_ids` ordering validation (`verify_dex_bytes()`).
- Output `system.img` is audited end-to-end with `fsck.erofs` (0 errors) and `dump.erofs` (9,524 inodes, 0 unlabeled SELinux files).
