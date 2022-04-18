# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022 The LineageOS Project

LOCAL_PATH := $(call my-dir)

ifneq ($(filter crownlte, $(TARGET_DEVICE)),)
include $(call all-subdir-makefiles,$(LOCAL_PATH))
endif
