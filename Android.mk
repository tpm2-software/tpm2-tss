LOCAL_PATH:= $(call my-dir)

LOCAL_COMMON_C_INCLUDES := $(addprefix $(LOCAL_PATH)/, include sysapi/include)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := libtss2.0-marshal
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := marshal/base-types.c log/log.c
LOCAL_CXX_STL := none

LOCAL_C_INCLUDES := $(LOCAL_COMMON_C_INCLUDES)

include $(BUILD_STATIC_LIBRARY)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := libtss2.0-common
LOCAL_MODULE_TAGS := optional
# src expects project relative, make needs repo relative paths, thus
# strip LOCAL_PATH when done.
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,, $(wildcard $(LOCAL_PATH)/common/*.c))
LOCAL_CXX_STL := none

LOCAL_C_INCLUDES := $(LOCAL_COMMON_C_INCLUDES)

include $(BUILD_STATIC_LIBRARY)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := libtss2.0
LOCAL_MODULE_TAGS := optional

# src expects project relative, make needs repo relative paths, thus
# strip LOCAL_PATH when done.
LOCAL_SYSAPI_SRC := $(subst $(LOCAL_PATH)/,, $(wildcard $(LOCAL_PATH)/sysapi/sysapi/*.c))
LOCAL_SYSAPIUTIL_SRC = $(subst $(LOCAL_PATH)/,, $(wildcard $(LOCAL_PATH)/sysapi/sysapi_util/*.c))
LOCAL_SRC_FILES := $(LOCAL_SYSAPI_SRC) $(LOCAL_SYSAPIUTIL_SRC)

LOCAL_CXX_STL := none

LOCAL_C_INCLUDES := $(LOCAL_COMMON_C_INCLUDES)

LOCAL_STATIC_LIBRARIES := libtss2.0-marshal libtss2.0-common

include $(BUILD_SHARED_LIBRARY)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := libtcti_device

LOCAL_C_INCLUDES := $(LOCAL_COMMON_C_INCLUDES)

LOCAL_SRC_FILES := tcti/tcti_device.c tcti/commonchecks.c
LOCAL_MODULE_TAGS := optional
LOCAL_CXX_STL := none

LOCAL_STATIC_LIBRARIES := libtss2.0-marshal libtss2.0-common

include $(BUILD_SHARED_LIBRARY)
