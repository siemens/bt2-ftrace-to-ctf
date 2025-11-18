/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <babeltrace2/babeltrace.h>

#define _LOG_PREFIX "[bt-ftrace]"

// clang-format off
#define BT_FTRACE_LOG(self_level, msg_level, level_name, msg, ...) \
	do {                                                     \
		if (msg_level >= self_level) { \
			fprintf(stderr, _LOG_PREFIX "[" level_name "] " msg "\n", ##__VA_ARGS__); \
		} \
	} while (0)

#define BT_FTRACE_LOG_DEBUG(self_level, msg, ...)                   \
	BT_FTRACE_LOG(self_level, BT_LOGGING_LEVEL_DEBUG, "debug", msg, ##__VA_ARGS__)
#define BT_FTRACE_LOG_INFO(self_level, msg, ...) \
	BT_FTRACE_LOG(self_level, BT_LOGGING_LEVEL_INFO, "info", msg, ##__VA_ARGS__)
#define BT_FTRACE_LOG_WARNING(self_level, msg, ...)                     \
	BT_FTRACE_LOG(self_level, BT_LOGGING_LEVEL_WARNING, "warning", msg, ##__VA_ARGS__)
#define BT_FTRACE_LOG_ERROR(self_level, msg, ...)                     \
	BT_FTRACE_LOG(self_level, BT_LOGGING_LEVEL_ERROR, "error", msg, ##__VA_ARGS__)
// clang-format on
