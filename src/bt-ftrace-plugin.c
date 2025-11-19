/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Babeltrace2 plugin to work with ftrace (trace.dat) data
 * 
 */

#include <babeltrace2/babeltrace.h>

#include "bt-ftrace-source.h"

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
