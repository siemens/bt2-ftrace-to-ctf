/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_SOURCE_LIVE_H
#define _BT_FTRACE_SOURCE_LIVE_H

#include <babeltrace2/babeltrace.h>
#include <tracefs.h>
#include <uuid.h>

struct tracefs_instance *ftrace_live_open_existing_instance(const char *path,
															char **tracing_dir);

char *ftrace_live_derive_uid(void);

int ftrace_live_derive_trace_uid(const char *tracing_dir, const char *uid_seed,
								 char uid[UUID_STR_LEN]);

bt_component_class_initialize_method_status
ftrace_live_initialize(bt_self_component_source *self_component_source,
					   bt_self_component_source_configuration *configuration,
					   const bt_value *params, void *initialize_method_data);

void ftrace_live_finalize(bt_self_component_source *self_component_source);

bt_message_iterator_class_initialize_method_status
ftrace_live_message_iterator_initialize(
	bt_self_message_iterator *self_message_iterator,
	bt_self_message_iterator_configuration *configuration,
	bt_self_component_port_output *self_port);

void ftrace_live_message_iterator_finalize(
	bt_self_message_iterator *self_message_iterator);

bt_message_iterator_class_next_method_status ftrace_live_message_iterator_next(
	bt_self_message_iterator *self_message_iterator,
	bt_message_array_const messages, uint64_t capacity, uint64_t *count);

bt_component_class_get_supported_mip_versions_method_status
ftrace_live_get_supported_mip_versions(
	bt_self_component_class_source *self_component_class,
	const bt_value *params, void *initialize_method_data,
	bt_logging_level logging_level,
	bt_integer_range_set_unsigned *supported_versions);

#endif
