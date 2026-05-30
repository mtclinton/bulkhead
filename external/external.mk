# SPDX-License-Identifier: AGPL-3.0-only
# Include every bulkhead package recipe under package/<name>/<name>.mk
include $(sort $(wildcard $(BR2_EXTERNAL_BULKHEAD_PATH)/package/*/*.mk))
