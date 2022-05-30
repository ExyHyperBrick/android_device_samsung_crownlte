# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022 The LineageOS Project

DEVICE_PACKAGE_OVERLAYS += $(LOCAL_PATH)/overlay

# Inherit from the common tree
$(call inherit-product, device/samsung/exynos9810-common/common.mk)

# Inherit proprietary files
$(call inherit-product, vendor/samsung/crownlte/crownlte-vendor.mk)

# Setup dalvik vm configs
$(call inherit-product, frameworks/native/build/phone-xhdpi-6144-dalvik-heap.mk)
