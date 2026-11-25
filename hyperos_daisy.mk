# Copyright (C) 2026 Riajul (Riajul18-19)
# Product Configuration for HyperOS 4 (Android 17) on Xiaomi Mi A2 Lite (daisy)
# SPDX-License-Identifier: Apache-2.0

$(call inherit-product, device/xiaomi/daisy/device.mk)

PRODUCT_NAME := hyperos_daisy
PRODUCT_DEVICE := daisy
PRODUCT_BRAND := Xiaomi
PRODUCT_MANUFACTURER := Xiaomi
PRODUCT_MODEL := Mi A2 Lite

PRODUCT_GMS_CLIENTID_BASE := android-xiaomi

PRODUCT_BUILD_PROP_OVERRIDES += \
    BuildDesc="daisy-user 17.0 HyperOS 4.0.0.20 release-keys" \
    DeviceName="daisy" \
    DeviceProduct="daisy"
