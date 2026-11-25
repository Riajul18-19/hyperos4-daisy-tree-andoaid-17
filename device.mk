# Copyright (C) 2026 Riajul (Riajul18-19)
# Device Tree Configuration for Xiaomi Mi A2 Lite (daisy)
# SPDX-License-Identifier: Apache-2.0

# Enforce 1080x2280 LCD density matching vendor/build.prop
PRODUCT_AAPT_CONFIG := normal
PRODUCT_AAPT_PREF_CONFIG := xxhdpi
PRODUCT_AAPT_PREBUILT_DPI := xxhdpi xhdpi hdpi

# Kernel & First Stage Ramdisk
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/kernel/prebuilt/Image.gz-dtb:kernel \
    $(LOCAL_PATH)/ramdisk/first_stage_ramdisk/fstab.qcom:$(TARGET_COPY_OUT_RAMDISK)/fstab.qcom \
    $(LOCAL_PATH)/ramdisk/prop.default:$(TARGET_COPY_OUT_RAMDISK)/prop.default

# Runtime Init & Performance Defaults (SDM625 / Adreno 506 / 3GB zRAM)
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/rootdir/bin/daisy_init_defaults.sh:$(TARGET_COPY_OUT_SYSTEM)/bin/daisy_init_defaults.sh \
    $(LOCAL_PATH)/rootdir/etc/perfinit.conf:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/perfinit.conf \
    $(LOCAL_PATH)/rootdir/etc/init/hw/init.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/hw/init.rc \
    $(LOCAL_PATH)/rootdir/etc/init/init.miui.ext.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.miui.ext.rc \
    $(LOCAL_PATH)/rootdir/etc/init/netbpfload.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/netbpfload.rc \
    $(LOCAL_PATH)/rootdir/etc/init/perfetto.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/perfetto.rc

# Hidden API Exemptions & Legacy HAL VINTF Compatibility
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/sysconfig/miui_whitelist.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/sysconfig/miui_whitelist.xml \
    $(LOCAL_PATH)/configs/vintf/manifest.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/vintf/manifest.xml

# System, Product & Extension Properties
TARGET_SYSTEM_PROP += $(LOCAL_PATH)/configs/props/system.prop
TARGET_PRODUCT_PROP += $(LOCAL_PATH)/configs/props/product.prop
TARGET_SYSTEM_EXT_PROP += $(LOCAL_PATH)/configs/props/system_ext.prop

# A/B Updater Services
PRODUCT_PACKAGES += \
    update_engine \
    update_engine_sideload \
    update_verifier

# Build Characteristics
PRODUCT_CHARACTERISTICS := nosdcard
