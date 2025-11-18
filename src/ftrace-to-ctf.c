/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Construct and execute graph to convert ftrace data (from trace-cmd's
 * trace.dat) to CTF.
 */
#include <babeltrace2/babeltrace.h>
#include <libgen.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

/* Structure that holds the parsed options */
typedef struct {
	bool lttng;
	char *ctf_version;
	uint64_t clock_offset;
	int mip;
	char *trace_path;
	char *out_dir;
} prog_opts;

static void print_usage(char *prog_name)
{
	fprintf(
		stderr,
		"Usage: %s [-clh] <trace.dat> <outdir>\n"
		"\n"
		"Options:\n"
		"  -c, --ctf-version <v> CTF version to use (default: 1.8)\n"
		"  -l, --lttng           Convert well-known events to LTTng representation (default: off)\n"
		"  -o, --clock-offset <offset> Trace clock offset in ns to world clock\n"
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
	opts->ctf_version = "1.8";
	opts->mip = 0;
	opts->lttng = false;
	opts->clock_offset = 0;
	opts->trace_path = NULL;
	opts->out_dir = NULL;

	// clang-format off
	static const struct option long_opts[] = {
		{ "ctf-version", required_argument, 0 , 'c'},
		{ "clock-offset", required_argument, 0, 'o'},
		{ "lttng",       no_argument,       0, 'l' },
		{ "help",        no_argument,       0, 'h' },
		{ 0,             0,                 0,  0  }
	};
	// clang-format on

	int opt;
	int opt_index = 0;

	while ((opt = getopt_long(argc, argv, "c:lho:", long_opts, &opt_index)) !=
		   -1) {
		switch (opt) {
		case 'c':
			opts->ctf_version = optarg;
			break;
		case 'l':
			opts->lttng = true;
			break;
		case 'o':
			opts->clock_offset = strtoull(optarg, NULL, 10);
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
	if (positional_left != 2) {
		fprintf(stderr,
				"Error: expected exactly two positional arguments, got %d.\n",
				positional_left);
		print_usage(argv[0]);
		return 1;
	}

	opts->trace_path = argv[optind];
	opts->out_dir = argv[optind + 1];

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

int main(int argc, char **argv)
{
	const bt_component_source *source = NULL;
	const bt_component_filter *filter = NULL;
	const bt_component_sink *sink = NULL;

	prog_opts opts;

	if (parse_args(argc, argv, &opts) != 0) {
		return -1;
	}

	printf("Options parsed:\n");
	printf("  lttng :       %s\n", opts.lttng ? "yes" : "no");
	printf("  ctf-version : %s\n", opts.ctf_version);
	printf("  clock-offset: %lu\n", opts.clock_offset);
	printf("  trace   :     %s\n", opts.trace_path);
	printf("  outdir  :     %s\n", opts.out_dir);

	const bt_plugin *ftrace_plugin = load_plugin_by_name("ftrace");
	if (!ftrace_plugin)
		return -1;

	const bt_plugin *utils_plugin = load_plugin_by_name("utils");
	if (!utils_plugin)
		return -1;

	const bt_plugin *ctf_plugin = load_plugin_by_name("ctf");
	if (!ctf_plugin)
		return -1;

	const bt_component_class_source *source_cls =
		bt_plugin_borrow_source_component_class_by_name_const(ftrace_plugin,
															  "tracedat");

	const bt_component_class_filter *filter_cls =
		bt_plugin_borrow_filter_component_class_by_name_const(utils_plugin,
															  "muxer");

	const bt_component_class_sink *sink_cls =
		bt_plugin_borrow_sink_component_class_by_name_const(ctf_plugin, "fs");

	bt_graph *graph = bt_graph_create(opts.mip);

	bt_value *inputs;
	bt_value *source_params = bt_value_map_create();
	bt_value_map_insert_empty_array_entry(source_params, "inputs", &inputs);
	bt_value_array_append_string_element(inputs, opts.trace_path);
	bt_value_map_insert_bool_entry(source_params, "lttng", opts.lttng);
	bt_value_map_insert_unsigned_integer_entry(source_params, "clock-offset",
											   opts.clock_offset);
	bt_graph_add_source_component(graph, source_cls, "ftrace", source_params,
								  BT_LOGGING_LEVEL_WARNING, &source);
	bt_value_put_ref(source_params);

	bt_graph_add_filter_component(graph, filter_cls, "muxer", NULL,
								  BT_LOGGING_LEVEL_WARNING, &filter);

	bt_value *sink_params = bt_value_map_create();
	bt_value_map_insert_string_entry(sink_params, "path", opts.out_dir);
	bt_value_map_insert_string_entry(sink_params, "ctf-version",
									 opts.ctf_version);
	bt_graph_add_sink_component(graph, sink_cls, "fs", sink_params,
								BT_LOGGING_LEVEL_WARNING, &sink);
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

	const bt_port_output *f_out =
		bt_component_filter_borrow_output_port_by_index_const(filter, 0);
	const bt_port_input *s_in =
		bt_component_sink_borrow_input_port_by_index_const(sink, 0);
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
