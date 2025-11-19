/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_TRACEMETA_H
#define _BT_FTRACE_TRACEMETA_H

#include <babeltrace2/babeltrace.h>

bt_component_class_initialize_method_status
tracemeta_out_initialize(bt_self_component_sink *self_component_sink,
						 bt_self_component_sink_configuration *configuration,
						 const bt_value *params, void *initialize_method_data);

void tracemeta_out_finalize(bt_self_component_sink *self_component_sink);

bt_component_class_sink_graph_is_configured_method_status
tracemeta_out_graph_is_configured(bt_self_component_sink *self_component_sink);

bt_component_class_sink_consume_method_status
tracemeta_out_consume(bt_self_component_sink *self_component_sink);

bt_component_class_get_supported_mip_versions_method_status
tracemeta_out_get_supported_mip_versions(
	bt_self_component_class_sink *const self_component_class,
	const bt_value *const params, void *const initialize_method_data,
	const bt_logging_level logging_level,
	bt_integer_range_set_unsigned *const supported_versions);

#endif
