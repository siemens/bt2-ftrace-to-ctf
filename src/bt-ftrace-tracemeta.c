/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * The tracemeta sink emits per-stream clock metadata in json-lines format that
 * can be used to sync the clocks of multiple traces. The format is as following:
 * {
 *   stream: { id: <int>, name: <str>},
 *   clock: { offset_s: <int>, offset_c: <int>, frequency: <int> }
 * }
 * The sink component uses the following initialization parameters:
 * 
 * "outfd": int, optional: file descriptor to write output data to
 * 
 */

#include "bt-ftrace-tracemeta.h"
#include "bt-ftrace-logging.h"

#include <babeltrace2/babeltrace.h>
#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <uuid.h>

struct tracemeta_out {
	/* Logging */
	bt_logging_level log_level;

	/* Where to emit metadata */
	int fd_out;

	/* Upstream message iterator (owned by this) */
	bt_message_iterator *message_iterator;
	uint64_t mip_version;
};

bt_component_class_initialize_method_status
tracemeta_out_initialize(bt_self_component_sink *self_component_sink,
						 bt_self_component_sink_configuration *configuration,
						 const bt_value *params, void *initialize_method_data)
{
	struct tracemeta_out *tracemeta_out = calloc(1, sizeof(*tracemeta_out));
	tracemeta_out->fd_out = fileno(stdout);

	tracemeta_out->log_level =
		bt_component_get_logging_level(bt_component_sink_as_component_const(
			bt_self_component_sink_as_component_sink(self_component_sink)));
	tracemeta_out->mip_version = bt_self_component_get_graph_mip_version(
		bt_self_component_sink_as_self_component(self_component_sink));

	const bt_value *output =
		bt_value_map_borrow_entry_value_const(params, "outfd");
	if (output) {
		tracemeta_out->fd_out = bt_value_integer_signed_get(output);
	}

	bt_self_component_set_data(
		bt_self_component_sink_as_self_component(self_component_sink),
		tracemeta_out);
	bt_self_component_sink_add_input_port(self_component_sink, "in", NULL,
										  NULL);

	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

void tracemeta_out_finalize(bt_self_component_sink *self_component_sink)
{
	struct tracemeta_out *tracemeta_out = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink));

	BT_MESSAGE_ITERATOR_PUT_REF_AND_RESET(tracemeta_out->message_iterator);
	free(tracemeta_out);
}

bt_component_class_sink_graph_is_configured_method_status
tracemeta_out_graph_is_configured(bt_self_component_sink *self_component_sink)
{
	/* Retrieve our private data from the component's user data */
	struct tracemeta_out *tracemeta_out = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink));

	/* Borrow our unique port */
	bt_self_component_port_input *in_port =
		bt_self_component_sink_borrow_input_port_by_index(self_component_sink,
														  0);

	/* Create the upstream message iterator */
	bt_message_iterator_create_from_sink_component(
		self_component_sink, in_port, &tracemeta_out->message_iterator);

	return BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_OK;
}

static void emit_metadata_json(struct tracemeta_out *cm_out,
							   const bt_message *message)
{
	int64_t offset_sec;
	uint64_t offset_cycles, freq;
	bt_uuid clock_uuid = NULL;

	const bt_stream *stream =
		bt_message_stream_beginning_borrow_stream_const(message);
	const bt_clock_class *clock_cls =
		bt_message_stream_beginning_borrow_stream_class_default_clock_class_const(
			message);
	bt_clock_class_get_offset(clock_cls, &offset_sec, &offset_cycles);
	freq = bt_clock_class_get_frequency(clock_cls);
	if (cm_out->mip_version == 0) {
		clock_uuid = bt_clock_class_get_uuid(clock_cls);
	}

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder);

	/* stream object */
	json_builder_set_member_name(builder, "stream");
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "id");
	json_builder_add_int_value(builder, (gint64)bt_stream_get_id(stream));

	json_builder_set_member_name(builder, "name");
	const char *sname = bt_stream_get_name(stream);
	json_builder_add_string_value(builder, sname ? sname : "");
	json_builder_end_object(builder);

	/* clock object */
	json_builder_set_member_name(builder, "clock");
	json_builder_begin_object(builder);

	json_builder_set_member_name(builder, "offset_s");
	json_builder_add_int_value(builder, (gint64)offset_sec);

	json_builder_set_member_name(builder, "offset_c");
	json_builder_add_int_value(builder, (gint64)offset_cycles);

	json_builder_set_member_name(builder, "frequency");
	json_builder_add_int_value(builder, (gint64)freq);

	if (clock_uuid) {
		char uuid_buf[UUID_STR_LEN];
		uuid_unparse(clock_uuid, uuid_buf);
		json_builder_set_member_name(builder, "uuid");
		json_builder_add_string_value(builder, uuid_buf);
	} else if (cm_out->mip_version > 0) {
#if BT2_VERSION_MINOR >= 1
		const char *clock_uid = bt_clock_class_get_uid(clock_cls);
		json_builder_set_member_name(builder, "uid");
		json_builder_add_string_value(builder, clock_uid);
#endif
	}

	json_builder_end_object(builder);

	json_builder_end_object(builder);

	JsonNode *root = json_builder_get_root(builder);

	JsonGenerator *gen = json_generator_new();
	json_generator_set_root(gen, root);
	gsize ser_len;
	gchar *serialized = json_generator_to_data(gen, &ser_len);
	write(cm_out->fd_out, serialized, ser_len);
	write(cm_out->fd_out, "\n", 1);
	g_free(serialized);

	g_object_unref(gen);
	json_node_free(root);
	g_object_unref(builder);
}

bt_component_class_sink_consume_method_status
tracemeta_out_consume(bt_self_component_sink *self_component_sink)
{
	bt_component_class_sink_consume_method_status status =
		BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;

	/* Retrieve our private data from the component's user data */
	struct tracemeta_out *tracemeta_out = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_component_sink));

	/* Consume a batch of messages from the upstream message iterator */
	bt_message_array_const messages;
	uint64_t message_count;
	bt_message_iterator_next_status next_status = bt_message_iterator_next(
		tracemeta_out->message_iterator, &messages, &message_count);

	switch (next_status) {
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_END:
		/* End of iteration: put the message iterator's reference */
		BT_MESSAGE_ITERATOR_PUT_REF_AND_RESET(tracemeta_out->message_iterator);
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_END;
		goto end;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_AGAIN:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_AGAIN;
		goto end;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_MEMORY_ERROR:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_MEMORY_ERROR;
		goto end;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_ERROR:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
		goto end;
	default:
		break;
	}

	/* For each consumed message */
	for (uint64_t i = 0; i < message_count; i++) {
		/* Current message */
		const bt_message *message = messages[i];

		if (bt_message_get_type(message) == BT_MESSAGE_TYPE_STREAM_BEGINNING) {
			emit_metadata_json(tracemeta_out, message);
		}

		/* Put this message's reference */
		bt_message_put_ref(message);
	}

end:
	return status;
}

bt_component_class_get_supported_mip_versions_method_status
tracemeta_out_get_supported_mip_versions(
	bt_self_component_class_sink *const self_component_class,
	const bt_value *const params, void *const initialize_method_data,
	const bt_logging_level logging_level,
	bt_integer_range_set_unsigned *const supported_versions)
{
	if (bt_integer_range_set_unsigned_add_range(supported_versions, 0, 1) !=
		BT_INTEGER_RANGE_SET_ADD_RANGE_STATUS_OK) {
		return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_MEMORY_ERROR;
	}

	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}
