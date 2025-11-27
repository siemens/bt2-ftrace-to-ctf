/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <babeltrace2/babeltrace.h>

bt_component_class_initialize_method_status
ftrace_in_initialize(bt_self_component_source *self_component_source,
					 bt_self_component_source_configuration *configuration,
					 const bt_value *params, void *initialize_method_data);

void ftrace_in_finalize(bt_self_component_source *self_component_source);

bt_message_iterator_class_initialize_method_status
ftrace_in_message_iterator_initialize(
	bt_self_message_iterator *self_message_iterator,
	bt_self_message_iterator_configuration *configuration,
	bt_self_component_port_output *self_port);

void ftrace_in_message_iterator_finalize(
	bt_self_message_iterator *self_message_iterator);

bt_message_iterator_class_next_method_status
ftrace_in_message_iterator_next(bt_self_message_iterator *self_message_iterator,
								bt_message_array_const messages,
								uint64_t capacity, uint64_t *count);

/* seek interface */
bt_message_iterator_class_seek_beginning_method_status
ftrace_in_message_iterator_seek_beginning(
	bt_self_message_iterator *self_message_iterator);

bt_message_iterator_class_can_seek_beginning_method_status
ftrace_in_message_iterator_can_seek_beginning(
	bt_self_message_iterator *self_message_iterator, bt_bool *can_seek);
bt_message_iterator_class_seek_ns_from_origin_method_status
ftrace_in_message_iterator_seek_ns_from_origin(
	bt_self_message_iterator *self_message_iterator, int64_t ns_from_origin);
bt_message_iterator_class_can_seek_ns_from_origin_method_status
ftrace_in_message_iterator_can_seek_ns_from_origin(
	bt_self_message_iterator *self_message_iterator, int64_t ns_from_origin,
	bt_bool *can_seek);

bt_component_class_get_supported_mip_versions_method_status
ftrace_get_supported_mip_versions(
	bt_self_component_class_source *const self_component_class,
	const bt_value *const params, void *const initialize_method_data,
	const bt_logging_level logging_level,
	bt_integer_range_set_unsigned *const supported_versions);
