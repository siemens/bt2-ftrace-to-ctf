/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Construct and execute graph to convert ftrace data (from trace-cmd's
 * trace.dat) to CTF.
 */
#include <babeltrace2/babeltrace.h>
#include <json-glib/json-glib.h>
#include <libgen.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <uuid.h>

/* Structure that holds the parsed options */
typedef struct {
	char *begin;
	bool lttng;
	char *ctf_version;
	uint64_t clock_offset;
	char *clock_uid;
	char *end;
	int mip;
	char *trace_datetime;
	char *trace_name;
	char *trace_path;
	char *lttng_path;
	char *out_dir;
	int loglevel;
} prog_opts;

typedef struct {
	char *clock_uid;
	int64_t clock_offset_s;
	uint64_t clock_offset_c;
	uint64_t clock_freq;
	char *trace_datetime;
	char *trace_name;
} trace_metadata;

static void print_usage(char *prog_name)
{
	fprintf(
		stderr,
		"Usage: %s [-clh] <trace.dat> [<lttng-trace>] <outdir>\n"
		"\n"
		"Options:\n"
		"  -b, --begin <ts>      skip until (babeltrace2-filter.utils.trimmer begin input)\n"
		"  -c, --ctf-version <v> CTF version to use (default: 1.8)\n"
		"  -d, --trace-dt <name> ISO‑8601 timestamp of the trace\n"
		"  -e, --end <ts>        trim after (babeltrace2-filter.utils.trimmer end input)\n"
		"  -l, --lttng           Convert well-known events to LTTng representation (default: off)\n"
		"  -n, --trace-name <name> Name of the trace (session)\n"
		"  -o, --clock-offset <offset> Trace clock offset in ns to world clock\n"
		"  -u, --clock-uid <(u)uid> Trace clock uuid or uid, depending on MIP version\n"
		"  -v, --verbose         Increase logging level (repeatable)\n"
		"  -h, --help            Show this help message and exit\n",
		basename(prog_name));
}

/* 
 * checks if the CTF version is supported and writes the corresponding MIP version
 * to the output parameter mip_version. The sink.ctf.fs sink only supports CTF 1.8
 * on MIP 0 and CTF 2 on MIP 1.
 */
static bool check_ctf_version(const char *ctf_version, int *mip_version)
{
	if (!ctf_version || !mip_version)
		return false;

	if (strcmp(ctf_version, "1") == 0 || strcmp(ctf_version, "1.8") == 0) {
		*mip_version = 0;
		return true;
	} else if (strcmp(ctf_version, "2") == 0) {
		*mip_version = 1;
		return true;
	}
	return false;
}

int parse_args(int argc, char *argv[], prog_opts *opts)
{
	/* Initialise defaults */
	memset(opts, 0, sizeof(*opts));
	opts->ctf_version = "1.8";
	opts->loglevel = BT_LOGGING_LEVEL_WARNING;

	// clang-format off
	static const struct option long_opts[] = {
		{ "begin",       required_argument, 0, 'b' },
		{ "ctf-version", required_argument, 0 , 'c'},
		{ "clock-offset", required_argument, 0, 'o'},
		{ "clock-uid",   required_argument, 0, 'u' },
		{ "end",         required_argument, 0, 'e' },
		{ "lttng",       no_argument,       0, 'l' },
		{ "trace-dt",    required_argument, 0, 'd' },
		{ "trace-name",  required_argument, 0, 'n' },
		{ "verbose",     no_argument,       0, 'v' },
		{ "help",        no_argument,       0, 'h' },
		{ 0,             0,                 0,  0  }
	};
	// clang-format on

	int opt;
	int opt_index = 0;

	while ((opt = getopt_long(argc, argv, "b:c:d:e:ln:o:u:vh", long_opts,
							  &opt_index)) != -1) {
		switch (opt) {
		case 'b':
			opts->begin = strdup(optarg);
			break;
		case 'c':
			opts->ctf_version = optarg;
			break;
		case 'd':
			opts->trace_datetime = strdup(optarg);
			break;
		case 'e':
			opts->end = strdup(optarg);
			break;
		case 'l':
			opts->lttng = true;
			break;
		case 'n':
			opts->trace_name = strdup(optarg);
			break;
		case 'o':
			opts->clock_offset = strtoull(optarg, NULL, 10);
			break;
		case 'u':
			opts->clock_uid = strdup(optarg);
			break;
		case 'v':
			opts->loglevel = opts->loglevel > 0 ? opts->loglevel - 1 : 0;
			break;
		case 'h': /* fall‑through */
		case '?': /* unknown option */
			print_usage(argv[0]);
			return 1;

		default:
			/* Should never happen */
			return 1;
		}
	}

	/* After option processing, the remaining arguments are positional */
	int positional_left = argc - optind;
	if (positional_left < 2 || positional_left > 3) {
		fprintf(stderr,
				"Error: expected two or three positional arguments, got %d.\n",
				positional_left);
		print_usage(argv[0]);
		return 1;
	}

	opts->trace_path = argv[optind];
	if (positional_left == 3) {
		opts->lttng_path = argv[optind + 1];
		opts->out_dir = argv[optind + 2];
	} else {
		opts->out_dir = argv[optind + 1];
	}

	/* Sanity check inputs */
	if (!check_ctf_version(opts->ctf_version, &opts->mip)) {
		fprintf(stderr,
				"Error: unsupported CTF version \"%s\".\n"
				"Allowed values are: 1, 1.8, 2.\n",
				opts->ctf_version);
		print_usage(argv[0]);
		return 1;
	}
	if (access(opts->trace_path, R_OK) != 0) {
		perror("cannot read trace file");
		return 1;
	}
	if (access(opts->out_dir, W_OK) != 0) {
		perror("cannot write to output directory");
		return 1;
	}

	return 0;
}

/*
 * Helper to insert a trimmer parameter.
 * If the value can be parsed as a signed integer, insert it as such;
 * otherwise insert it as a string.
 */
static void insert_trimmer_param(bt_value *params, const char *key,
								 const char *value)
{
	char *endptr;
	long long val = strtoll(value, &endptr, 10);
	if (*endptr == '\0') {
		bt_value_map_insert_signed_integer_entry(params, key, (int64_t)val);
	} else {
		bt_value_map_insert_string_entry(params, key, value);
	}
}

const bt_plugin *load_plugin_by_name(char *name)
{
	const bt_plugin *plugin;
	bt_plugin_find_status status;
	status = bt_plugin_find(name, true, true, true, false, false, &plugin);

	if (status == BT_PLUGIN_FIND_STATUS_OK) {
		return plugin;
	}
	printf("cannot find plugin \"%s\"\n", name);
	return NULL;
}

/* Parse the clock definitions emitted by sink.ftrace.tracemeta */
static int parse_trace_meta(const char *buffer, trace_metadata *trace_meta)
{
	JsonParser *parser = json_parser_new();
	GError *error = NULL;

	if (!json_parser_load_from_data(parser, buffer, -1, &error)) {
		g_printerr("Failed to parse JSON: %s\n", error->message);
		g_error_free(error);
		g_object_unref(parser);
		return -1;
	}

	JsonNode *root = json_parser_get_root(parser);
	JsonObject *root_o = json_node_get_object(root);

	if (!json_object_has_member(root_o, "clock")) {
		g_printerr("JSON object does not contain a \"clock\" member.\n");
		g_object_unref(parser);
		return -1;
	}

	JsonObject *clock_o = json_object_get_object_member(root_o, "clock");

	if (!json_object_has_member(clock_o, "offset_s") ||
		!json_object_has_member(clock_o, "offset_c") ||
		!json_object_has_member(clock_o, "frequency") ||
		!(json_object_has_member(clock_o, "uid") |
		  json_object_has_member(clock_o, "uuid"))) {
		g_printerr("\"clock\" object is missing one of the required fields.\n");
		g_object_unref(parser);
		return -1;
	}

	trace_meta->clock_offset_s =
		(guint64)json_object_get_int_member(clock_o, "offset_s");
	trace_meta->clock_offset_c =
		(guint64)json_object_get_int_member(clock_o, "offset_c");
	trace_meta->clock_freq =
		(guint64)json_object_get_int_member(clock_o, "frequency");
	const char *uid_str =
		json_object_get_string_member_with_default(clock_o, "uid", "");
	if (*uid_str) {
		trace_meta->clock_uid = strdup(uid_str);
	} else {
		/* Either uid or uuid must be set, so we can be sure to have it */
		const char *uuid_str = json_object_get_string_member(clock_o, "uuid");
		trace_meta->clock_uid = strdup(uuid_str);
	}

	JsonObject *env_o = json_object_get_object_member(root_o, "env");
	if (json_object_has_member(env_o, "trace_name")) {
		trace_meta->trace_name =
			strdup(json_object_get_string_member(env_o, "trace_name"));
	}
	if (json_object_has_member(env_o, "trace_creation_datetime")) {
		trace_meta->trace_datetime = strdup(
			json_object_get_string_member(env_o, "trace_creation_datetime"));
	}
	g_object_unref(parser);
	return 0;
}

/**
 * Create a babeltrace graph with the sink.ftrace.tracemeta component to
 * extract the clock definition of a stream (e.g. from a LTTng US CTF file).
 * Only a single iteration of the graph is executed as we just need a single
 * clock definition. Once we have it, we return it to the caller so that he
 * can create the clock accordingly.
 * 
 * Internally, the output of the sink is passed via a anonymous pipe.
 * 
 * Note: This parser needs to be kept in sync with the generator in
 * sink.ftrace.tracemeta.
 */
static int get_metadata_from_lttng_trace(const bt_plugin *ftrace_plugin,
										 const bt_plugin *ctf_plugin,
										 const bt_plugin *utils_plugin,
										 prog_opts *opts)
{
	const bt_component_source *source;
	const bt_component_filter *filter;
	const bt_component_sink *sink;
	trace_metadata trace_meta;
	int out_fds[2];
	int status = 0;

	memset(&trace_meta, 0, sizeof(trace_meta));

	const bt_component_class_source *source_cls =
		bt_plugin_borrow_source_component_class_by_name_const(ctf_plugin, "fs");
	const bt_component_class_filter *filter_cls =
		bt_plugin_borrow_filter_component_class_by_name_const(utils_plugin,
															  "muxer");

	const bt_component_class_sink *sink_cls =
		bt_plugin_borrow_sink_component_class_by_name_const(ftrace_plugin,
															"tracemeta");

	/* prepare in-memory file for output */
	pipe(out_fds);

	/* Construct graph */
	bt_graph *graph = bt_graph_create(opts->mip);

	/* add components */
	bt_value *inputs;
	bt_value *comp_params = bt_value_map_create();
	bt_value_map_insert_empty_array_entry(comp_params, "inputs", &inputs);
	bt_value_array_append_string_element(inputs, opts->lttng_path);
	bt_graph_add_source_component(graph, source_cls, "lttng", comp_params,
								  opts->loglevel, &source);
	bt_value_put_ref(comp_params);

	bt_graph_add_filter_component(graph, filter_cls, "muxer", NULL,
								  opts->loglevel, &filter);

	comp_params = bt_value_map_create();
	bt_value_map_insert_signed_integer_entry(comp_params, "outfd", out_fds[1]);

	bt_graph_add_sink_component(graph, sink_cls, "tracemeta", comp_params,
								opts->loglevel, &sink);
	bt_value_put_ref(comp_params);

	/* plumbing */
	const uint64_t nb_out_ports =
		bt_component_source_get_output_port_count(source);
	for (uint64_t i = 0; i < nb_out_ports; ++i) {
		const bt_port_output *s_out =
			bt_component_source_borrow_output_port_by_index_const(source, i);
		const bt_port_input *f_in =
			bt_component_filter_borrow_input_port_by_index_const(filter, i);
		bt_graph_connect_ports(graph, s_out, f_in, NULL);
	}
	const bt_port_output *f_out =
		bt_component_filter_borrow_output_port_by_index_const(filter, 0);
	const bt_port_input *s_in =
		bt_component_sink_borrow_input_port_by_index_const(sink, 0);
	bt_graph_connect_ports(graph, f_out, s_in, NULL);

	/* execute (we are interested in a single stream-beginning message)*/
	bt_graph_run_once_status run_status = bt_graph_run_once(graph);
	int error_status = 0;
	if (run_status == BT_GRAPH_RUN_ONCE_STATUS_ERROR) {
		fprintf(stderr, "Error running graph to get trace metadata\n");
		error_status = -1;
	}
	if (run_status == BT_GRAPH_RUN_ONCE_STATUS_MEMORY_ERROR) {
		fprintf(stderr, "Memory error running graph to get trace metadata\n");
		error_status = -1;
	}
	BT_GRAPH_PUT_REF_AND_RESET(graph);
	/* close writer end */
	close(out_fds[1]);
	/* exits with error after cleanup */
	if (error_status != 0) {
		close(out_fds[0]);
		return error_status;
	}

	FILE *fp = fdopen(out_fds[0], "r");
	if (!fp) {
		close(out_fds[0]);
		return -1;
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t nb = getline(&line, &len, fp);
	line[nb] = '\0';
	status = parse_trace_meta(line, &trace_meta);
	if (status == 0) {
		opts->clock_offset = trace_meta.clock_offset_s * trace_meta.clock_freq +
							 trace_meta.clock_offset_c;
		opts->clock_uid = trace_meta.clock_uid;
		opts->trace_datetime = trace_meta.trace_datetime;
		opts->trace_name = trace_meta.trace_name;
	}
	free(line);
	fclose(fp);
	return status;
}

int main(int argc, char **argv)
{
	const bt_component_source *source = NULL;
	const bt_component_source *source_lttng = NULL;
	const bt_component_filter *filter = NULL;
	const bt_component_filter *trimmer = NULL;
	const bt_component_sink *sink = NULL;

	prog_opts opts;

	if (parse_args(argc, argv, &opts) != 0) {
		return -1;
	}

	printf("Options parsed:\n");
	printf("  lttng :       %s\n", opts.lttng ? "yes" : "no");
	printf("  ctf-version : %s\n", opts.ctf_version);
	printf("  trace   :     %s\n", opts.trace_path);
	printf("  lttng-trace:  %s\n",
		   opts.lttng_path ? opts.lttng_path : "not provided");
	printf("  outdir  :     %s\n", opts.out_dir);
	if (opts.begin || opts.end) {
		printf("  begin  :     %s\n", opts.begin ? opts.begin : "not provided");
		printf("  end    :     %s\n", opts.end ? opts.end : "not provided");
	}

	const bt_plugin *ftrace_plugin = load_plugin_by_name("ftrace");
	if (!ftrace_plugin)
		return -1;

	const bt_plugin *utils_plugin = load_plugin_by_name("utils");
	if (!utils_plugin)
		return -1;

	const bt_plugin *ctf_plugin = load_plugin_by_name("ctf");
	if (!ctf_plugin)
		return -1;

	if (opts.lttng_path) {
		get_metadata_from_lttng_trace(ftrace_plugin, ctf_plugin, utils_plugin,
									  &opts);
	}
	printf("  clock-offset: %lu\n", opts.clock_offset);
	printf("  clock-uid:    %s\n",
		   opts.clock_uid ? opts.clock_uid : "not provided");
	printf("  trace-date:   %s\n",
		   opts.trace_datetime ? opts.trace_datetime : "not provided");
	printf("  trace-name:   %s\n",
		   opts.trace_name ? opts.trace_name : "not provided");

	int error_status = 0;
	const bt_component_class_source *source_cls =
		bt_plugin_borrow_source_component_class_by_name_const(ftrace_plugin,
															  "tracedat");
	if (source_cls == NULL) {
		fprintf(stderr, "cannot find source component class 'tracedat'\n");
		error_status = -1;
	}

	const bt_component_class_source *source_lttng_cls;
	if (opts.lttng_path) {
		source_lttng_cls =
			bt_plugin_borrow_source_component_class_by_name_const(ctf_plugin,
																  "fs");
		if (source_lttng_cls == NULL) {
			fprintf(stderr, "cannot find source component class 'fs'\n");
			error_status = -1;
		}
	}

	const bt_component_class_filter *filter_cls =
		bt_plugin_borrow_filter_component_class_by_name_const(utils_plugin,
															  "muxer");
	if (filter_cls == NULL) {
		fprintf(stderr, "cannot find filter component class 'muxer'\n");
		error_status = -1;
	}

	const bt_component_class_filter *trimmer_cls =
		bt_plugin_borrow_filter_component_class_by_name_const(utils_plugin,
															  "trimmer");
	if (trimmer_cls == NULL) {
		fprintf(stderr, "cannot find filter component class 'trimmer'\n");
		error_status = -1;
	}

	const bt_component_class_sink *sink_cls =
		bt_plugin_borrow_sink_component_class_by_name_const(ctf_plugin, "fs");

	if (sink_cls == NULL) {
		fprintf(stderr, "cannot find sink component class 'fs'\n");
		error_status = -1;
	}

	if (error_status != 0) {
		BT_PLUGIN_PUT_REF_AND_RESET(ftrace_plugin);
		BT_PLUGIN_PUT_REF_AND_RESET(utils_plugin);
		BT_PLUGIN_PUT_REF_AND_RESET(ctf_plugin);
		free(opts.begin);
		free(opts.end);
		return error_status;
	}

	bt_graph *graph = bt_graph_create(opts.mip);

	bt_value *inputs;
	bt_value *source_params = bt_value_map_create();
	bt_value_map_insert_empty_array_entry(source_params, "inputs", &inputs);
	bt_value_array_append_string_element(inputs, opts.trace_path);
	bt_value_map_insert_bool_entry(source_params, "lttng", opts.lttng);
	bt_value_map_insert_unsigned_integer_entry(source_params, "clock-offset",
											   opts.clock_offset);
	if (opts.clock_uid) {
		bt_value_map_insert_string_entry(source_params, "clock-uid",
										 opts.clock_uid);
	}
	if (opts.trace_name) {
		bt_value_map_insert_string_entry(source_params, "trace-name",
										 opts.trace_name);
	}
	if (opts.trace_datetime) {
		bt_value_map_insert_string_entry(
			source_params, "trace-creation-datetime", opts.trace_datetime);
	}
	bt_graph_add_source_component(graph, source_cls, "ftrace", source_params,
								  opts.loglevel, &source);
	bt_value_put_ref(source_params);
	free(opts.clock_uid);
	free(opts.trace_datetime);
	free(opts.trace_name);

	/* optional lttng trace input */
	if (opts.lttng_path) {
		source_params = bt_value_map_create();
		bt_value_map_insert_empty_array_entry(source_params, "inputs", &inputs);
		bt_value_array_append_string_element(inputs, opts.lttng_path);
		bt_graph_add_source_component(graph, source_lttng_cls, "lttng",
									  source_params, opts.loglevel,
									  &source_lttng);
		bt_value_put_ref(source_params);
	}

	bt_graph_add_filter_component(graph, filter_cls, "muxer", NULL,
								  opts.loglevel, &filter);

	if (opts.begin || opts.end) {
		bt_value *trimmer_params = bt_value_map_create();
		if (opts.begin) {
			insert_trimmer_param(trimmer_params, "begin", opts.begin);
		}
		if (opts.end) {
			insert_trimmer_param(trimmer_params, "end", opts.end);
		}
		bt_graph_add_filter_component(graph, trimmer_cls, "trimmer",
									  trimmer_params, opts.loglevel, &trimmer);
		bt_value_put_ref(trimmer_params);
	}
	free(opts.begin);
	free(opts.end);

	/* sink component */
	unsigned int p_major = 0;
	bt_plugin_get_version(ctf_plugin, &p_major, NULL, NULL, NULL);
	bt_value *sink_params = bt_value_map_create();
	bt_value_map_insert_string_entry(sink_params, "path", opts.out_dir);

	/*
	 * The CTF sink has very strict limitations regarding the time ranges of
	 * discarded events. As these do not match the ranges reported by trace-cmd
	 * (e.g. we cannot relate discarded events to packets), we just disable this
	 * feature. For details, see
	 * https://babeltrace.org/docs/v2.1/man7/babeltrace2-sink.ctf.fs.7
	 */
	bt_value_map_insert_bool_entry(sink_params, "ignore-discarded-events",
								   true);

	/* 
	 * this parameter is only available from plugin version 2.1 on, but
	 * the plugin registers as version 2.0.0 (on 2.1) and does not set a
	 * version on prior versions.
	 */
	if (p_major >= 2) {
		bt_value_map_insert_string_entry(sink_params, "ctf-version",
										 opts.ctf_version);
	} else if (strcmp(opts.ctf_version, "2") == 0) {
		fprintf(stderr, "on babeltrace 2.0, only CTF 1.8 is supported.\n");
	}
	bt_graph_add_sink_component(graph, sink_cls, "fs", sink_params,
								opts.loglevel, &sink);
	bt_value_put_ref(sink_params);

	const uint64_t nb_ft_ports =
		bt_component_source_get_output_port_count(source);
	for (uint64_t i = 0; i < nb_ft_ports; ++i) {
		const bt_port_output *ft_out =
			bt_component_source_borrow_output_port_by_index_const(source, i);
		const bt_port_input *f_in =
			bt_component_filter_borrow_input_port_by_index_const(filter, i);
		bt_graph_connect_ports(graph, ft_out, f_in, NULL);
	}
	/* plumbing of optional lttng source */
	if (opts.lttng_path) {
		const uint64_t nb_lttng_ports =
			bt_component_source_get_output_port_count(source_lttng);
		for (uint64_t i = 0; i < nb_lttng_ports; ++i) {
			const bt_port_output *lttng_out =
				bt_component_source_borrow_output_port_by_index_const(
					source_lttng, i);
			const bt_port_input *f_in =
				bt_component_filter_borrow_input_port_by_index_const(
					filter, i + nb_ft_ports);
			bt_graph_connect_ports(graph, lttng_out, f_in, NULL);
		}
	}

	const bt_port_output *f_out =
		bt_component_filter_borrow_output_port_by_index_const(filter, 0);
	const bt_port_input *s_in =
		bt_component_sink_borrow_input_port_by_index_const(sink, 0);

	if (trimmer) {
		const bt_port_input *t_in =
			bt_component_filter_borrow_input_port_by_index_const(trimmer, 0);
		const bt_port_output *t_out =
			bt_component_filter_borrow_output_port_by_index_const(trimmer, 0);
		/* loop in the trimmer */
		bt_graph_connect_ports(graph, f_out, t_in, NULL);
		f_out = t_out;
	}
	bt_graph_connect_ports(graph, f_out, s_in, NULL);

	bt_graph_run_once_status status;
	bt_bool is_running = 1;
	while (is_running) {
		status = bt_graph_run_once(graph);
		switch (status) {
		case BT_GRAPH_RUN_ONCE_STATUS_OK:
			break;
		case BT_GRAPH_RUN_ONCE_STATUS_END:
			is_running = 0;
			break;
		case BT_GRAPH_RUN_ONCE_STATUS_AGAIN:
			break;
		case BT_GRAPH_RUN_ONCE_STATUS_MEMORY_ERROR:
			is_running = 0;
			printf("memory error\n");
			break;
		case BT_GRAPH_RUN_ONCE_STATUS_ERROR:
			is_running = 0;
			printf("other error\n");
			break;
		}
	}
	if (status != BT_GRAPH_RUN_ONCE_STATUS_END) {
		printf("graph execution failed\n");
	}

	BT_GRAPH_PUT_REF_AND_RESET(graph);
	BT_PLUGIN_PUT_REF_AND_RESET(ftrace_plugin);
	BT_PLUGIN_PUT_REF_AND_RESET(utils_plugin);
	BT_PLUGIN_PUT_REF_AND_RESET(ctf_plugin);

	return 0;
}
