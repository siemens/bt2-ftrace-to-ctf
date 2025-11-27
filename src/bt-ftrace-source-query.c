/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * 
 * Implements the babeltrace query interface of source.ftrace.tracedat
 */

#define _GNU_SOURCE

#include <sched.h>
#include <trace-cmd.h>
#include <event-parse.h>
#include <babeltrace2/babeltrace.h>

#include "bt-ftrace-source-query.h"

/*
 * Implements the babeltrace.support-info query interface.
 */
static bt_component_class_query_method_status
ftrace_query_support_info(bt_self_component_class_source *self_component_class,
						  bt_private_query_executor *query_executor,
						  const bt_value *params, void *method_data,
						  const bt_value **result)
{
	const bt_value *type_val =
		bt_value_map_borrow_entry_value_const(params, "type");
	const bt_value *name_val =
		bt_value_map_borrow_entry_value_const(params, "input");
	if (!type_val || !name_val) {
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	}
	if (strcmp(bt_value_string_get(type_val), "file") != 0) {
		goto nothing_discovered;
	}
	struct tracecmd_input *tc_in = tracecmd_open_head(
		bt_value_string_get(name_val), TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!tc_in)
		goto nothing_discovered;
	tracecmd_close(tc_in);
	*result = bt_value_real_create_init(1);
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;

nothing_discovered:
	*result = bt_value_real_create_init(0);
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
}

#if HAS_TRACECMD_REVERSE_ITERATION
static int get_last_record_ts_clbk(struct tracecmd_input *tc_input,
								   struct tep_record *rec, int cpu,
								   void *userdata)
{
	uint64_t *ts_end = (uint64_t *)userdata;
	*ts_end = rec->ts;
	/* stop iteration */
	return -1;
}
#endif

/*
 * Implements the babeltrace.trace-infos query interface.
 */
static bt_component_class_query_method_status
ftrace_query_trace_infos(bt_self_component_class_source *self_component_class,
						 bt_private_query_executor *query_executor,
						 const bt_value *params, void *method_data,
						 const bt_value **result)
{
	char NAME_BUF[32];
	const bt_value *inputs =
		bt_value_map_borrow_entry_value_const(params, "inputs");
	if (!inputs)
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	if (!bt_value_is_array(inputs) || !bt_value_array_get_length(inputs))
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	const bt_value *path_value =
		bt_value_array_borrow_element_by_index_const(inputs, 0);
	const char *path = bt_value_string_get(path_value);

	struct tracecmd_input *tc_input =
		tracecmd_open(path, TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!tc_input) {
		return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
	}

	struct tep_handle *tep = tracecmd_get_tep(tc_input);
	const int ncpus = tep_get_cpus(tep);

	bt_value *response = bt_value_map_create();
	bt_value *infos, *streaminfo, *range;
	bt_value_map_insert_empty_array_entry(response, "stream-infos", &infos);
	const uint64_t ts_begin = tracecmd_get_first_ts(tc_input);
	for (int i = 0; i < ncpus; ++i) {
		sprintf(NAME_BUF, "out%d", i);
		bt_value_array_append_empty_map_element(infos, &streaminfo);
		bt_value_map_insert_string_entry(streaminfo, "port-name", NAME_BUF);
		bt_value_map_insert_empty_map_entry(streaminfo, "range-ns", &range);
		bt_value_map_insert_signed_integer_entry(range, "begin-ns",
												 (int64_t)ts_begin);
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);
		CPU_SET(i, &cpu_set);
		uint64_t ts_end = ts_begin;
#if HAS_TRACECMD_REVERSE_ITERATION
		/* 
		 * O(1) implementation, potentially with upstream memory leak as reported in
		 * https://lore.kernel.org/linux-trace-devel/20251121134749.1530855-1-felix.moessbauer@siemens.com/
		 */
		tracecmd_iterate_events_reverse(tc_input, &cpu_set, ncpus,
										get_last_record_ts_clbk,
										(void *)&ts_end, 0);
#else
		/* O(n) implementation iterating the whole trace file */
		struct tep_record *rec = tracecmd_read_cpu_first(tc_input, i);
		while (rec) {
			ts_end = rec->ts;
			tracecmd_free_record(rec);
			rec = tracecmd_read_data(tc_input, i);
		}
#endif
		bt_value_map_insert_signed_integer_entry(range, "end-ns", ts_end);
	}

	tracecmd_close(tc_input);
	*result = response;
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
}

/* Implements the babeltrace query interface */
bt_component_class_query_method_status
ftrace_query_method(bt_self_component_class_source *self_component_class,
					bt_private_query_executor *query_executor,
					const char *object_name, const bt_value *params,
					void *method_data, const bt_value **result)
{
	if (strcmp(object_name, "babeltrace.support-info") == 0) {
		return ftrace_query_support_info(self_component_class, query_executor,
										 params, method_data, result);
	}
	if (strcmp(object_name, "babeltrace.trace-infos") == 0) {
		return ftrace_query_trace_infos(self_component_class, query_executor,
										params, method_data, result);
	}
	return BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
}
