/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_SOURCE_LIVE_QUERY_H
#define _BT_FTRACE_SOURCE_LIVE_QUERY_H

#include <babeltrace2/babeltrace.h>

bt_component_class_query_method_status
ftrace_live_query_method(bt_self_component_class_source *self_component_class,
						 bt_private_query_executor *query_executor,
						 const char *object_name, const bt_value *params,
						 void *method_data, const bt_value **result);

#endif /* _BT_FTRACE_SOURCE_LIVE_QUERY_H */
