/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_SOURCE_QUERY_H
#define _BT_FTRACE_SOURCE_QUERY_H

#include <babeltrace2/babeltrace.h>
#include <stdint.h>

struct tracecmd_input;

bt_component_class_query_method_status
ftrace_query_method(bt_self_component_class_source *self_component_class,
					bt_private_query_executor *query_executor,
					const char *object_name, const bt_value *params,
					void *method_data, const bt_value **result);

uint64_t get_buffer_end_ts(struct tracecmd_input *tc_input);

#endif
