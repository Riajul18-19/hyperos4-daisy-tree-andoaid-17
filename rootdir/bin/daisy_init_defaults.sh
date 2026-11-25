#!/system/bin/sh
# Xiaomi Mi A2 Lite (daisy) HyperOS 4 Android 17 runtime defaults
# Maintainer: Riajul

# 0. Single-execution guard per boot (only run once PackageManager & Settings are ready)
if [ -f /dev/.daisy_init_completed ]; then
    exit 0
fi

# Wait for PackageManagerService (prevents silent pm/settings failures on early boot)
for _i in $(seq 1 30); do
    if pm path android >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Disable iorapd on Kernel 4.9
setprop persist.sys.stability.PrereadEnable false
stop iorapd 2>/dev/null

# Silence SELinux audit flooding
echo 0 > /proc/sys/kernel/audit_ratelimit 2>/dev/null
auditctl -e 0 2>/dev/null

# Default Light Theme (clean, bright, zero glass)
cmd uimode night no 2>/dev/null
settings put secure ui_night_mode 1
settings put system is_night_mode 0
setprop persist.sys.theme 0

# 1. API Policy & Safe Mode Neutralization
settings put global hidden_api_policy 1
settings put global hidden_api_policy_pre_p_apps 1
settings put global hidden_api_policy_p_apps 1
settings put global hidden_api_blacklist_exemptions '*'
settings put global sys.rescueparty.home.level 0
settings delete global is_safe_mode
settings put global device_name "Xiaomi A2 Lite"
settings put system device_name "Xiaomi A2 Lite"
setprop persist.private.device_name "Xiaomi A2 Lite"
setprop persist.sys.device_name "Xiaomi A2 Lite"
settings put system screen_key_press_app_switch 1
cmd package set-home-activity com.miui.home/com.miui.home.launcher.Launcher 2>/dev/null

# 2. Google Play Services, Play Store & Google Autofill Native Integration
pm enable com.google.android.gms 2>/dev/null
pm enable com.google.android.gsf 2>/dev/null
pm enable com.android.vending 2>/dev/null
settings put secure miui_google_service_enable 1
settings put global miui_google_service_enable 1
setprop persist.sys.miui.google 1

# Google Autofill & Credential Provider Native Configuration
settings put secure autofill_service com.google.android.gms/com.google.android.gms.autofill.service.AutofillService
settings put secure credential_service com.google.android.gms/com.google.android.gms.auth.api.credentials.CredentialProviderService
settings put secure credential_service_primary com.google.android.gms/com.google.android.gms.auth.api.credentials.CredentialProviderService
settings put secure autofill_user_data_max_category_count 10
settings put secure autofill_user_data_max_field_classification_ids_size 10
settings put secure autofill_user_data_max_user_data_size 10000
settings put secure autofill_user_data_max_value_length 100
settings put secure autofill_user_data_min_value_length 2
settings put secure autofill_logging_level 0
appops set com.google.android.gms AUTOFILL allow 2>/dev/null
pm grant com.google.android.gms android.permission.BIND_AUTOFILL_SERVICE 2>/dev/null

# 3. Daisy Native 2G/3G/4G Network, Radio & Device-MAC WiFi Optimization
settings put global wifi_connected_mac_randomization_enabled 0
WCFG="/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml"
if [ -f "$WCFG" ] && grep -qE 'name="MacRandomizationSetting" value="[123]"' "$WCFG"; then
    sed -i 's/<int name="MacRandomizationSetting" value="[123]" \/>/<int name="MacRandomizationSetting" value="0" \/>/g' "$WCFG"
    cmd wifi set-wifi-enabled disabled 2>/dev/null
    sleep 1
    cmd wifi set-wifi-enabled enabled 2>/dev/null
fi
settings put global mobile_data_always_on 1
settings put global preferred_network_mode 9
settings put global preferred_network_mode1 9
setprop persist.vendor.radio.add_power_save 0
setprop persist.vendor.radio.data_con_rprt 1
setprop persist.vendor.radio.bar_evdo 1
setprop persist.vendor.radio.data_ltd_sys_ind 1
setprop persist.vendor.radio.ignore_dom_time 1
setprop persist.vendor.radio.snapshot_enabled 1
setprop persist.vendor.radio.snapshot_timer 3
setprop persist.vendor.radio.flexmap_type none
setprop persist.radio.multisim.config dsds
setprop persist.vendor.radio.apm_sim_not_pwdn 1
setprop persist.vendor.radio.custom_ecc 1

# 4. Gesture Navigation & Low Latency Swipe-up Response
settings put secure navigation_mode 2
settings put global force_fsg_nav_bar 1
settings put secure hide_gesture_line 0
settings put secure back_gesture_inset_scale_left 1.0
settings put secure back_gesture_inset_scale_right 1.0
settings put system fsg_gesture_sensitivity 1
settings put secure long_press_timeout 250
settings put secure multi_press_timeout 250
cmd overlay enable com.android.internal.systemui.navbar.gestural 2>/dev/null
cmd overlay enable com.android.systemui.gesture.line.overlay 2>/dev/null

# Snappy 0.75x Animation Scales (Immediate response on SDM625)
settings put global window_animation_scale 0.5
settings put global transition_animation_scale 0.5
settings put global animator_duration_scale 0.5

# 5. Lighter Vibrating Haptic Feedback (Gentle & refined)
settings put system haptic_feedback_level 1
settings put system haptic_feedback_intensity 1
settings put system sys_vibrate_intensity 1
settings put system notification_vibration_intensity 1
settings put system ring_vibration_intensity 1
settings put system keyboard_vibrate_intensity 1
settings put secure haptic_feedback_level 1
settings put secure haptic_feedback_intensity 1
settings put secure vibrator_level 1
echo 1800 > /sys/class/timed_output/vibrator/vtg_level 2>/dev/null || echo 1800 > /sys/class/leds/vibrator/vmax 2>/dev/null

# 6. Volume Dialog Glass Effect / Blur Permanently Disabled (No Green Screen)
setprop persist.sys.miui.volume_blur 0
setprop persist.sys.support_view_smoothcorner false
setprop persist.sys.support_window_smoothcorner false
setprop persist.sys.device.animation_hwui_corner_supported false
setprop persist.sys.device.freeform_hwui_corner_supported false
pm disable vendor.qti.imsdatachannel 2>/dev/null
setprop persist.sys.background_blur_supported false
setprop persist.sys.background_blur_status_default false
setprop persist.sys.background_blur_setting 0
setprop persist.sys.miui_blur_disable 1
setprop persist.sys.real_blur_minify 0
settings put system background_blur_enable 0
settings put secure background_blur_enable 0
settings put global background_blur_enable 0
settings put system advanced_textures 0
settings put secure advanced_textures 0
settings put global advanced_textures 0
setprop persist.sys.advanced_textures 0

# 7. Hardware Media Codec & Video Playback Acceleration (Snapdragon 625 Native OMX)
setprop persist.sys.force_sw_gles 0
setprop debug.sf.disable_backpressure 0
setprop debug.stagefright.ccodec 0
setprop debug.stagefright.omx_default_rank 0
setprop debug.renderengine.backend skiagl
setprop debug.hwui.renderer skiagl
setprop debug.sf.disable_client_composition_cache 0
setprop debug.sf.predict_hwc_composition_strategy 1
setprop debug.sf.latch_unsignaled 1
setprop debug.sf.enable_gl_backpressure 1
setprop video.accelerate.hw 1
setprop debug.egl.hw 1
setprop debug.sf.hw 1
setprop sys.use_fifo_ui 1
pm enable com.google.android.apps.wallpaper 2>/dev/null
pm enable com.android.incallui 2>/dev/null
pm enable com.android.thememanager 2>/dev/null

# 8. Lock Screen & Native Customizable Keyguard Clock (100% Preserved & Working)
cmd lock_settings set-disabled false 2>/dev/null
settings put secure lockscreen.disabled 0
settings put global lockscreen_disabled 0
settings put system lockscreen.disabled 0
settings put secure lock_screen_lock_after_timeout 0
settings put secure lock_screen_lock_on_power_button 1
settings put secure lock_pattern_autolock 1
settings put secure lock_screen_owner_info_enabled 1
settings put system lock_screen_clock_display_type 1
settings put system keyguard_clock_position 1
settings put secure selected_keyguard_clock_position 1
settings put system auto_dual_clock 0
settings put secure lockscreen_use_double_line_clock 1
settings put secure lock_screen_show_notifications 1
# Auto-heal legacy pre-MIUIAod single-row lockscreen clock missing ":" and fontStyle
CUR_CTEI=$(settings get secure constant_template_editor_info 2>/dev/null)
if echo "$CUR_CTEI" | grep -q '"fontStyle":0' && echo "$CUR_CTEI" | grep -q '"isColonShow":false' && echo "$CUR_CTEI" | grep -q '"isDoubleRow":false'; then
    settings delete secure constant_template_editor_info 2>/dev/null
    killall com.android.systemui 2>/dev/null || true
fi
# Keep AOD off by default on IPS LCD while keeping MIUIAod KEYGUARD_EDITOR available
settings put secure doze_always_on 0
settings put secure aod_mode 0
pm enable com.miui.aod 2>/dev/null

# 9. Runtime permissions & appops for MIUI Home
pm grant com.miui.home android.permission.READ_EXTERNAL_STORAGE 2>/dev/null
pm grant com.miui.home android.permission.WRITE_EXTERNAL_STORAGE 2>/dev/null
pm grant com.miui.home android.permission.READ_MEDIA_IMAGES 2>/dev/null
pm grant com.miui.home android.permission.READ_MEDIA_VIDEO 2>/dev/null
pm grant com.miui.home android.permission.READ_MEDIA_AUDIO 2>/dev/null
pm grant com.miui.home android.permission.POST_NOTIFICATIONS 2>/dev/null
pm grant com.miui.home android.permission.READ_PHONE_STATE 2>/dev/null
pm grant com.miui.home android.permission.CALL_PHONE 2>/dev/null
pm grant com.miui.home android.permission.CAMERA 2>/dev/null
pm grant com.miui.home android.permission.READ_CALENDAR 2>/dev/null
pm grant com.miui.home android.permission.WRITE_CALENDAR 2>/dev/null
pm grant com.miui.home android.permission.READ_CONTACTS 2>/dev/null
pm grant com.miui.home android.permission.WRITE_CONTACTS 2>/dev/null
pm grant com.miui.home android.permission.ACCESS_FINE_LOCATION 2>/dev/null
pm grant com.miui.home android.permission.ACCESS_COARSE_LOCATION 2>/dev/null
pm grant com.miui.home android.permission.ACCESS_MEDIA_LOCATION 2>/dev/null
appops set com.miui.home ACCESS_RESTRICTED_SETTINGS allow 2>/dev/null
appops set com.miui.home GET_USAGE_STATS allow 2>/dev/null
appops set com.miui.home SYSTEM_ALERT_WINDOW allow 2>/dev/null
appops set com.miui.home WRITE_SETTINGS allow 2>/dev/null
appops set com.miui.home MANAGE_EXTERNAL_STORAGE allow 2>/dev/null
appops set com.miui.home LEGACY_STORAGE allow 2>/dev/null

# 10. Default Wallpaper Initialization
mkdir -p /data/system/theme
mkdir -p /data/system/theme_magic/users/0/wallpaper/image
mkdir -p /data/system/theme_magic/users/0/wallpaper/default
mkdir -p /data/system/theme_magic/users/0/wallpaper/data
mkdir -p /data/system/users/0

WP_SRC="/system/etc/wallpaper_defaults/lock_wallpaper.jpg"
if [ ! -f "$WP_SRC" ]; then
    WP_SRC="/product/media/theme/default/lock_wallpaper"
fi
if [ ! -f "$WP_SRC" ]; then
    WP_SRC="/product/etc/precust_theme/theme/.data/content/wallpaper/c00e4951-8932-4149-912f-7300cf9c867b.mrc"
fi

if [ -f "$WP_SRC" ]; then
    cp "$WP_SRC" /data/system/theme/lock_wallpaper 2>/dev/null
    chown 9801:9801 /data/system/theme/lock_wallpaper 2>/dev/null || chown system:system /data/system/theme/lock_wallpaper 2>/dev/null
    chmod 644 /data/system/theme/lock_wallpaper 2>/dev/null

    if [ ! -f /data/system/theme_magic/users/0/wallpaper/image/lock_wallpaper.jpg ]; then
        cp "$WP_SRC" /data/system/theme_magic/users/0/wallpaper/image/lock_wallpaper.jpg 2>/dev/null
        cp "$WP_SRC" /data/system/theme_magic/users/0/wallpaper/image/home_wallpaper.jpg 2>/dev/null
        cp "$WP_SRC" /data/system/theme_magic/users/0/wallpaper/default/lock_wallpaper.jpg 2>/dev/null
        cp "$WP_SRC" /data/system/theme_magic/users/0/wallpaper/default/home_wallpaper.jpg 2>/dev/null
        chmod -R 666 /data/system/theme_magic/users/0/wallpaper/image/* 2>/dev/null
        chmod -R 666 /data/system/theme_magic/users/0/wallpaper/default/* 2>/dev/null
    fi

    if [ ! -f /data/system/users/0/wallpaper ]; then
        cp "$WP_SRC" /data/system/users/0/wallpaper 2>/dev/null
        cp "$WP_SRC" /data/system/users/0/wallpaper_lock 2>/dev/null
        cp "$WP_SRC" /data/system/users/0/wallpaper_orig 2>/dev/null
        cp "$WP_SRC" /data/system/users/0/wallpaper_lock_orig 2>/dev/null
        chown -R system:system /data/system/users/0/wallpaper* 2>/dev/null
        chmod 600 /data/system/users/0/wallpaper* 2>/dev/null
    fi
fi

if [ ! -f /data/system/theme_magic/users/0/wallpaper/data/lock.xml ]; then
    if [ -f /system/etc/wallpaper_defaults/lock.xml ]; then
        cp /system/etc/wallpaper_defaults/lock.xml /data/system/theme_magic/users/0/wallpaper/data/lock.xml 2>/dev/null
        cp /system/etc/wallpaper_defaults/home.xml /data/system/theme_magic/users/0/wallpaper/data/home.xml 2>/dev/null
    else
        cat << 'EOF' > /data/system/theme_magic/users/0/wallpaper/data/lock.xml
<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<theme_wallpaper_data type="image" effect_id="0" blend_color="0" style="1" />
EOF
        cat << 'EOF' > /data/system/theme_magic/users/0/wallpaper/data/home.xml
<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<theme_wallpaper_data type="image" effect_id="0" blend_color="0" style="1" />
EOF
    fi
    chmod 666 /data/system/theme_magic/users/0/wallpaper/data/*.xml 2>/dev/null
fi

# 11. Xiaomi HyperAI Permanently Disabled
setprop service.aiseal.enable 0
setprop persist.service.aiseal.enable 0
stop aisealhostservice 2>/dev/null

# 12. Compact Control Center & Status Bar Flanking Notch
settings put system use_control_panel 1
settings put system battery_indicator_style 1
settings put system status_bar_show_network_speed 0
settings put system status_bar_show_vibrate_icon 0
settings put system status_bar_show_notification_icon 1
settings put system quick_center_small 1

# 13. Snapdragon 625 (MSM8953) ZRAM & Memory Optimization (Reduced Overhead, Zero Feature Loss)
setprop persist.debug.dalvik.vm.jdwp.enabled 0
setprop persist.debug.perfetto.persistent_sysui_tracing_for_bugreport 0
if [ -b /dev/block/zram0 ]; then
    CUR_ZRAM="$(cat /sys/block/zram0/disksize 2>/dev/null)"
    if [ "$CUR_ZRAM" != "2147483648" ]; then
        swapoff /dev/block/zram0 2>/dev/null
        echo 1 > /sys/block/zram0/reset 2>/dev/null
        echo lz4 > /sys/block/zram0/comp_algorithm 2>/dev/null
        echo 2147483648 > /sys/block/zram0/disksize 2>/dev/null
        mkswap /dev/block/zram0 2>/dev/null
        swapon /dev/block/zram0 -p 32758 2>/dev/null
    fi
fi
echo 100 > /proc/sys/vm/vfs_cache_pressure 2>/dev/null
echo 100 > /proc/sys/vm/swappiness 2>/dev/null
echo 0 > /proc/sys/vm/page-cluster 2>/dev/null
echo 15 > /proc/sys/vm/dirty_ratio 2>/dev/null
echo 5 > /proc/sys/vm/dirty_background_ratio 2>/dev/null
echo 4096 > /proc/sys/vm/min_free_kbytes 2>/dev/null
echo 24300 > /proc/sys/vm/extra_free_kbytes 2>/dev/null

# 14. eMMC 5.1 Storage I/O Optimization (Fast Reboot & Smooth App Launch)
for q in /sys/block/mmcblk0/queue; do
    if [ -d "$q" ]; then
        echo 512 > "$q/read_ahead_kb" 2>/dev/null
        echo 0 > "$q/iostats" 2>/dev/null
        echo 2 > "$q/rq_affinity" 2>/dev/null
        echo noop > "$q/scheduler" 2>/dev/null || echo cfq > "$q/scheduler" 2>/dev/null || echo mq-deadline > "$q/scheduler" 2>/dev/null
    fi
done

# 15. MSM8953 CPU (Schedutil + Input Boost + Cpusets) & Adreno 506 GPU Tuning
for c in /sys/devices/system/cpu/cpu[0-7]; do
    echo 1 > "$c/online" 2>/dev/null
    echo schedutil > "$c/cpufreq/scaling_governor" 2>/dev/null || echo interactive > "$c/cpufreq/scaling_governor" 2>/dev/null
done
for sd in /sys/devices/system/cpu/cpufreq/schedutil /sys/devices/system/cpu/cpu0/cpufreq/schedutil; do
    if [ -d "$sd" ]; then
        echo 500 > "$sd/up_rate_limit_us" 2>/dev/null
        echo 20000 > "$sd/down_rate_limit_us" 2>/dev/null
        echo 1689600 > "$sd/hispeed_freq" 2>/dev/null
        echo 80 > "$sd/hispeed_load" 2>/dev/null
        echo 1 > "$sd/iowait_boost_enable" 2>/dev/null
    fi
done
if [ -d /sys/module/cpu_boost/parameters ]; then
    echo "0:1401600 1:1401600 2:1401600 3:1401600 4:0 5:0 6:0 7:0" > /sys/module/cpu_boost/parameters/input_boost_freq 2>/dev/null
    echo 80 > /sys/module/cpu_boost/parameters/input_boost_ms 2>/dev/null
    echo 1 > /sys/module/cpu_boost/parameters/sched_boost_on_input 2>/dev/null
fi
echo "0-1" > /dev/cpuset/background/cpus 2>/dev/null
echo "0-2" > /dev/cpuset/system-background/cpus 2>/dev/null
echo "0-3" > /dev/cpuset/restricted/cpus 2>/dev/null
echo "0-7" > /dev/cpuset/foreground/cpus 2>/dev/null
echo "0-7" > /dev/cpuset/top-app/cpus 2>/dev/null

KGSL="/sys/class/kgsl/kgsl-3d0"
if [ -d "$KGSL" ]; then
    echo msm-adreno-tz > "$KGSL/devfreq/governor" 2>/dev/null
    echo 10 > "$KGSL/devfreq/polling_interval" 2>/dev/null
    echo 64 > "$KGSL/idle_timer" 2>/dev/null
    echo 1 > "$KGSL/bus_split" 2>/dev/null
    echo 1 > "$KGSL/hwcg" 2>/dev/null
    echo 1 > "$KGSL/preemption" 2>/dev/null
    echo 0 > "$KGSL/max_pwrlevel" 2>/dev/null
    echo 7 > "$KGSL/min_pwrlevel" 2>/dev/null
    echo 6 > "$KGSL/default_pwrlevel" 2>/dev/null
fi

# 16. Permanently Disable RescueParty
setprop persist.sys.enable_rescue 0
setprop persist.device_config.configuration.disable_rescue_party true
settings put global disable_rescue_party 1
settings put global rescue_party_disabled 1
settings put global sys.rescueparty.level 0
settings put global sys.rescueparty.home.level 0

touch /dev/.daisy_init_completed
