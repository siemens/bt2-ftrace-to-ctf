/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Babeltrace2 plugin to work with ftrace (trace.dat) data
 * 
 */

#include <babeltrace2/babeltrace.h>

#include "bt-ftrace-source.h"
#include "bt-ftrace-tracemeta.h"

/* Mandatory */
BT_PLUGIN_MODULE()

/* Define the `ftrace` plugin */
BT_PLUGIN(ftrace);

BT_PLUGIN_AUTHOR("Felix Moessbauer <felix.moessbauer@siemens.com>");
BT_PLUGIN_DESCRIPTION("Process kernel ftrace traces");
BT_PLUGIN_LICENSE("LGPL-2.1-or-later");

/* Define the `tracedat` source component class */
BT_PLUGIN_SOURCE_COMPONENT_CLASS(tracedat, ftrace_in_message_iterator_next);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_DESCRIPTION(
	tracedat, "import traces from trace-cmd's trace.dat file");

/* Set some of the `tracedat` source component class's optional methods */
BT_PLUGIN_SOURCE_COMPONENT_CLASS_INITIALIZE_METHOD(tracedat,
												   ftrace_in_initialize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_FINALIZE_METHOD(tracedat, ftrace_in_finalize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD(
	tracedat, ftrace_in_message_iterator_initialize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_FINALIZE_METHOD(
	tracedat, ftrace_in_message_iterator_finalize);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD(
	tracedat, ftrace_get_supported_mip_versions);
BT_PLUGIN_SOURCE_COMPONENT_CLASS_QUERY_METHOD(tracedat, ftrace_query_method);

/* Define the `tracemeta` sink component class */
BT_PLUGIN_SINK_COMPONENT_CLASS(tracemeta, tracemeta_out_consume);
BT_PLUGIN_SINK_COMPONENT_CLASS_DESCRIPTION(
	tracemeta, "emit per stream metadata of the trace clock");

BT_PLUGIN_SINK_COMPONENT_CLASS_INITIALIZE_METHOD(tracemeta,
												 tracemeta_out_initialize);
BT_PLUGIN_SINK_COMPONENT_CLASS_FINALIZE_METHOD(tracemeta,
											   tracemeta_out_finalize);
BT_PLUGIN_SINK_COMPONENT_CLASS_GRAPH_IS_CONFIGURED_METHOD(
	tracemeta, tracemeta_out_graph_is_configured);
BT_PLUGIN_SINK_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD(
	tracemeta, tracemeta_out_get_supported_mip_versions);
