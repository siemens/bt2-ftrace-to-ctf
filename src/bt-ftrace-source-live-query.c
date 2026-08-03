/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * 
 * Implements the babeltrace query interface of source.ftrace.live
 */

#include <tracefs.h>
#include <stdlib.h>

#include "bt-ftrace-common.h"
#include "bt-ftrace-source-live.h"
#include "bt-ftrace-source-live-query.h"

static bt_component_class_query_method_status
ftrace_live_query_support_info(const bt_value *params, const bt_value **result)
{
	const bt_value *type =
		bt_value_map_borrow_entry_value_const(params, "type");
	const bt_value *input =
		bt_value_map_borrow_entry_value_const(params, "input");
	struct tracefs_instance *instance;
	char *tracing_dir = NULL;
	char *tracing_on;
	char *uid_seed;
	char trace_uid[UUID_STR_LEN];
	char *group;
	int size;

	if (!type || !input || !bt_value_is_string(type) ||
		!bt_value_is_string(input) ||
		strcmp(bt_value_string_get(type), "directory") != 0) {
		*result = bt_value_real_create_init(0);
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
	}
	instance = ftrace_live_open_existing_instance(bt_value_string_get(input),
												  &tracing_dir);
	/* try to read tracing_on. No check if tracing is actually on */
	tracing_on = instance ?
					 tracefs_instance_file_read(instance, "tracing_on", &size) :
					 NULL;
	if (tracing_on) {
		free(tracing_on);
		uid_seed = ftrace_live_derive_uid();
		if (!uid_seed || ftrace_live_derive_trace_uid(tracing_dir, uid_seed,
													  trace_uid) < 0) {
			g_free(uid_seed);
			tracefs_instance_free(instance);
			free(tracing_dir);
			return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
		}
		g_free(uid_seed);
		group = g_strdup_printf("namespace: %s, name: , uid: %s",
								FTRACE_TRACE_NAMESPACE, trace_uid);
		bt_value *response = bt_value_map_create();
		bt_value_map_insert_real_entry(response, "weight", 1);
		bt_value_map_insert_string_entry(response, "group", group);
		g_free(group);
		*result = response;
	} else {
		*result = bt_value_real_create_init(0);
	}
	tracefs_instance_free(instance);
	free(tracing_dir);
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
}

static bt_component_class_query_method_status
ftrace_live_query_trace_infos(const bt_value *params, const bt_value **result)
{
	const bt_value *inputs;
	const bt_value *path_value;
	struct tracefs_instance *instance;
	struct tep_handle *tep;
	char *tracing_dir = NULL;
	bt_value *response;
	bt_value *trace_info;
	bt_value *stream_infos;
	struct ftrace_common_options options = { 0 };
	char trace_uid[UUID_STR_LEN];
	char *uid_seed;

	if (!params ||
		!(inputs = bt_value_map_borrow_entry_value_const(params, "inputs")) ||
		!bt_value_is_array(inputs) || bt_value_array_get_length(inputs) != 1) {
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	}
	path_value = bt_value_array_borrow_element_by_index_const(inputs, 0);
	if (!bt_value_is_string(path_value))
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	instance = ftrace_live_open_existing_instance(
		bt_value_string_get(path_value), &tracing_dir);
	if (!instance)
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	tep = tracefs_local_events(tracing_dir);
	if (!tep || tracefs_load_headers(tracing_dir, tep) < 0) {
		tep_free(tep);
		tracefs_instance_free(instance);
		free(tracing_dir);
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	}
	ftrace_parse_common_params(params, &options);
	uid_seed = ftrace_live_derive_uid();
	if (!uid_seed ||
		ftrace_live_derive_trace_uid(tracing_dir, uid_seed, trace_uid) < 0) {
		g_free(uid_seed);
		ftrace_common_opts_free(&options);
		tep_free(tep);
		tracefs_instance_free(instance);
		free(tracing_dir);
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	}
	g_free(uid_seed);
	response = bt_value_array_create();
	bt_value_array_append_empty_map_element(response, &trace_info);
	bt_value_map_insert_empty_array_entry(trace_info, "stream-infos",
										  &stream_infos);
	for (int cpu = 0; cpu < tep_get_cpus(tep); cpu++) {
		bt_value *stream_info;
		bt_value *range;
		const struct ftrace_trace_identity identity = {
			.namespace = FTRACE_TRACE_NAMESPACE,
			.name = options.trace_name ? options.trace_name : "",
			.uid = trace_uid,
		};
		char *port_name =
			ftrace_format_port_name(&identity, 0, cpu, tracing_dir);

		bt_value_array_append_empty_map_element(stream_infos, &stream_info);
		bt_value_map_insert_string_entry(stream_info, "port-name", port_name);
		g_free(port_name);
		bt_value_map_insert_empty_map_entry(stream_info, "range-ns", &range);
		bt_value_map_insert_signed_integer_entry(range, "begin", 0);
		bt_value_map_insert_signed_integer_entry(range, "end", INT64_MAX);
	}
	tep_free(tep);
	tracefs_instance_free(instance);
	free(tracing_dir);
	ftrace_common_opts_free(&options);
	*result = response;
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
}

bt_component_class_query_method_status
ftrace_live_query_method(bt_self_component_class_source *self_component_class,
						 bt_private_query_executor *query_executor,
						 const char *object_name, const bt_value *params,
						 void *method_data, const bt_value **result)
{
	if (strcmp(object_name, "babeltrace.support-info") == 0)
		return ftrace_live_query_support_info(params, result);
	if (strcmp(object_name, "babeltrace.trace-infos") == 0)
		return ftrace_live_query_trace_infos(params, result);
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
}
