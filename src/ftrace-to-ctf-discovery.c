/*
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 */

#include <babeltrace2/babeltrace.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "ftrace-to-ctf-discovery.h"

/* Append path and take ownership of group (which may be NULL). */
static void lttng_trace_list_append(lttng_trace_list *list, const char *path,
									char *group)
{
	if (list->count == list->cap) {
		size_t new_cap = list->cap ? list->cap * 2 : 8;
		lttng_trace_input *tmp = realloc(list->items, new_cap * sizeof(*tmp));
		if (!tmp) {
			free(group);
			return;
		}
		list->items = tmp;
		list->cap = new_cap;
	}
	list->items[list->count].path = strdup(path);
	list->items[list->count].group = group;
	list->count++;
}

void lttng_trace_list_clear(lttng_trace_list *list)
{
	for (size_t i = 0; i < list->count; ++i) {
		free(list->items[i].path);
		free(list->items[i].group);
	}
	free(list->items);
	list->items = NULL;
	list->count = 0;
	list->cap = 0;
}

/*
 * Query the given source component class whether it can handle 'path' as a
 * trace directory using the babeltrace.support-info query object. When 'group_out'
 * is non-NULL, it receives a newly-allocated copy of the reported group name
 * (or NULL if the input has no group); the caller owns that string.
 */
static double query_directory_support(const bt_component_class_source *cls,
									  const char *path, int loglevel,
									  char **group_out)
{
	if (group_out)
		*group_out = NULL;

	bt_value *params = bt_value_map_create();
	if (!params)
		return 0.0;
	bt_value_map_insert_string_entry(params, "type", "directory");
	bt_value_map_insert_string_entry(params, "input", path);

	bt_query_executor *qe = bt_query_executor_create(
		bt_component_class_source_as_component_class_const(cls),
		"babeltrace.support-info", params);
	bt_value_put_ref(params);
	if (!qe)
		return 0.0;
	bt_query_executor_set_logging_level(qe, loglevel);

	const bt_value *result = NULL;
	double weight = 0.0;
	if (bt_query_executor_query(qe, &result) ==
			BT_QUERY_EXECUTOR_QUERY_STATUS_OK &&
		result) {
		if (bt_value_is_real(result)) {
			weight = bt_value_real_get(result);
		} else if (bt_value_is_map(result)) {
			const bt_value *w =
				bt_value_map_borrow_entry_value_const(result, "weight");
			if (w && bt_value_is_real(w))
				weight = bt_value_real_get(w);
			if (group_out) {
				const bt_value *g =
					bt_value_map_borrow_entry_value_const(result, "group");
				if (g && bt_value_is_string(g))
					*group_out = strdup(bt_value_string_get(g));
			}
		}
		bt_value_put_ref(result);
	}
	bt_query_executor_put_ref(qe);
	return weight;
}

void discover_lttng_inputs(const bt_component_class_source *cls,
						   const char *path, lttng_trace_list *list,
						   int loglevel, bool verbose)
{
	char *group = NULL;
	if (verbose) {
		fprintf(stderr, "[ftrace-to-ctf][lttng discovery]: checking \"%s\"\n",
				path);
	}
	double weight = query_directory_support(cls, path, loglevel, &group);
	if (weight > 0.5) {
		if (verbose) {
			fprintf(
				stderr,
				"[ftrace-to-ctf][lttng discovery]: awarded \"%s\" (weight %.2f%s%s)\n",
				path, weight, group ? ", group " : "", group ? group : "");
		}
		/* list takes ownership of 'group' */
		lttng_trace_list_append(list, path, group);
		return;
	}
	free(group);

	DIR *dir = opendir(path);
	if (!dir)
		return;

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		char child[PATH_MAX];
		int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
		if (n < 0 || (size_t)n >= sizeof(child))
			continue;

		struct stat st;
		/* use lstat so that symlinks are not followed */
		if (lstat(child, &st) != 0 || !S_ISDIR(st.st_mode))
			continue;

		discover_lttng_inputs(cls, child, list, loglevel, verbose);
	}
	closedir(dir);
}
