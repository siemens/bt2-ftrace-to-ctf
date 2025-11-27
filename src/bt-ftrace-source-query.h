/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <babeltrace2/babeltrace.h>

bt_component_class_query_method_status
ftrace_query_method(bt_self_component_class_source *self_component_class,
					bt_private_query_executor *query_executor,
					const char *object_name, const bt_value *params,
					void *method_data, const bt_value **result);
