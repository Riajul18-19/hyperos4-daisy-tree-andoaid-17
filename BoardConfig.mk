# Copyright (C) 2026 Riajul (Riajul18-19)
# Board Configuration for Xiaomi Mi A2 Lite (daisy / MSM8953)
# Target OS: HyperOS 4 (Android 17) on Linux 4.9.337-Zero+
# SPDX-License-Identifier: Apache-2.0

DEVICE_PATH := device/xiaomi/daisy

# Platform & Architecture (14nm Qualcomm Snapdragon 625)
TARGET_ARCH := arm64
TARGET_ARCH_VARIANT := armv8-a
TARGET_CPU_ABI := arm64-v8a
TARGET_CPU_ABI2 :=
TARGET_CPU_VARIANT := cortex-a53

TARGET_2ND_ARCH := arm
TARGET_2ND_ARCH_VARIANT := armv8-a
TARGET_2ND_CPU_ABI := armeabi-v7a
TARGET_2ND_CPU_ABI2 := armeabi
TARGET_2ND_CPU_VARIANT := cortex-a53

TARGET_BOARD_PLATFORM := msm8953
TARGET_BOOTLOADER_BOARD_NAME := MSM8953

# Kernel & Boot Image (Legacy v0 header, Image.gz-dtb)
TARGET_KERNEL_ARCH := arm64
TARGET_KERNEL_HEADER_ARCH := arm64
TARGET_KERNEL_CONFIG := daisy_defconfig
TARGET_PREBUILT_KERNEL := $(DEVICE_PATH)/kernel/prebuilt/Image.gz-dtb

BOARD_KERNEL_BASE := 0x80008000
BOARD_KERNEL_PAGESIZE := 2048
BOARD_BOOT_HEADER_VERSION := 0
BOARD_KERNEL_CMDLINE := androidboot.hardware=qcom msm_rtb.filter=0x237 ehci-hcd.park=3 lpm_levels.sleep_disabled=1 androidboot.bootdevice=7824900.sdhci earlycon=msm_hsl_uart,0x78af000 loop.max_part=7 androidboot.boot_devices=soc/7824900.sdhci androidboot.selinux=permissive printk.devkmsg=on
BOARD_MKBOOTIMG_ARGS += --header_version $(BOARD_BOOT_HEADER_VERSION)

# A/B Non-Dynamic Legacy Partition Table (System-as-Root)
AB_OTA_UPDATER := true
AB_OTA_PARTITIONS += \
    boot \
    system \
    vendor

TARGET_NO_RECOVERY := true
BOARD_USES_RECOVERY_AS_BOOT := true
BOARD_BUILD_SYSTEM_ROOT_IMAGE := true

# Filesystems & Exact Flash Limits
# Legacy system_{a,b} physical size = 2,543,493,120 bytes (620,970 * 4096)
BOARD_EROFS_COMPRESSOR := lz4hc,12
BOARD_SYSTEMIMAGE_FILE_SYSTEM_TYPE := erofs
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 2543493120
BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_FLASH_BLOCK_SIZE := 131072

# Display (1080x2280 IPS LCD, Adreno 506)
TARGET_SCREEN_WIDTH := 1080
TARGET_SCREEN_HEIGHT := 2280
TARGET_SCREEN_DENSITY := 400

# SELinux & Security
BOARD_SEPOLICY_VERS := 202404.0
TARGET_FS_CONFIG_GEN := $(DEVICE_PATH)/configs/fs_config
