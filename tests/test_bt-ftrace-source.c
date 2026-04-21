#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <babeltrace2/babeltrace.h>
#include <stdlib.h>
#include <string.h>

#include "../src/bt-ftrace-source.h"

#ifndef TESTS_DIR
#error "TESTS_DIR must be defined by the build system"
#endif

#define TRACE_DAT_PATH (TESTS_DIR "/trace.dat")

static bt_component_class_source *create_ftrace_source_cc(void)
{
    bt_message_iterator_class *iter_class =
        bt_message_iterator_class_create(ftrace_in_message_iterator_next);
    if (!iter_class)
        return NULL;

    bt_message_iterator_class_set_initialize_method(
        iter_class, ftrace_in_message_iterator_initialize);
    bt_message_iterator_class_set_finalize_method(
        iter_class, ftrace_in_message_iterator_finalize);
    bt_message_iterator_class_set_seek_beginning_methods(
        iter_class,
        ftrace_in_message_iterator_seek_beginning,
        ftrace_in_message_iterator_can_seek_beginning);
    bt_message_iterator_class_set_seek_ns_from_origin_methods(
        iter_class,
        ftrace_in_message_iterator_seek_ns_from_origin,
        ftrace_in_message_iterator_can_seek_ns_from_origin);

    bt_component_class_source *src_cc =
        bt_component_class_source_create("ftrace.source", iter_class);

    bt_message_iterator_class_put_ref(iter_class);

    if (!src_cc)
        return NULL;

    bt_component_class_source_set_initialize_method(src_cc,
                                                     ftrace_in_initialize);
    bt_component_class_source_set_finalize_method(src_cc,
                                                   ftrace_in_finalize);
    bt_component_class_source_set_get_supported_mip_versions_method(
        src_cc, ftrace_get_supported_mip_versions);

    return src_cc;
}

static bt_value *make_params(const char *path)
{
    bt_value *params = bt_value_map_create();
    if (!params)
        return NULL;

    bt_value *inputs = bt_value_array_create();
    if (!inputs) {
        bt_value_put_ref(params);
        return NULL;
    }

    bt_value_array_append_string_element(inputs, path);
    bt_value_map_insert_entry(params, "inputs", inputs);
    bt_value_put_ref(inputs);

    return params;
}

typedef struct {
    bt_component_class_source *src_cc;
    bt_graph               *graph;
} test_state_t;

static int suite_setup(void **state)
{
    test_state_t *s = calloc(1, sizeof(*s));
    if (!s)
        return -1;

    bt_current_thread_clear_error();

    s->src_cc = create_ftrace_source_cc();
    if (!s->src_cc) {
        free(s);
        return -1;
    }

    s->graph = bt_graph_create(0);
    if (!s->graph) {
        bt_component_class_source_put_ref(s->src_cc);
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state)
{
    test_state_t *s = *state;
    if (s) {
        bt_graph_put_ref(s->graph);
        bt_component_class_source_put_ref(s->src_cc);
        free(s);
    }
    bt_current_thread_clear_error();
    return 0;
}

static int test_setup(void **state)
{
    (void)state;
    bt_current_thread_clear_error();
    return 0;
}

static int test_teardown(void **state)
{
    (void)state;
    bt_current_thread_clear_error();
    return 0;
}

static bt_graph_add_component_status add_source(
    test_state_t              *s,
    const bt_value            *params,
    const bt_component_source **out_comp)
{
    const bt_component_source *comp = NULL;
    bt_graph_add_component_status st =
        bt_graph_add_source_component(
            s->graph,
            s->src_cc,
            "test-src",
            params,
            BT_LOGGING_LEVEL_WARNING,
            &comp);

    if (out_comp)
        *out_comp = comp;

    return st;
}

static void test_ftrace_in_initialize_null_params(void **state)
{
    test_state_t *s = *state;

    bt_graph_add_component_status st = add_source(s, NULL, NULL);

    assert_int_equal(st, BT_GRAPH_ADD_COMPONENT_STATUS_ERROR);
}

static void test_ftrace_in_initialize_missing_inputs_key(void **state)
{
    test_state_t *s = *state;

    bt_value *params = bt_value_map_create();
    assert_non_null(params);
    bt_value_map_insert_string_entry(params, "lttng", "true");

    bt_graph_add_component_status st = add_source(s, params, NULL);
    bt_value_put_ref(params);

    assert_int_equal(st, BT_GRAPH_ADD_COMPONENT_STATUS_ERROR);
}

static void test_ftrace_in_initialize_empty_inputs_array(void **state)
{
    test_state_t *s = *state;

    bt_value *params = bt_value_map_create();
    assert_non_null(params);

    bt_value *inputs = bt_value_array_create();
    assert_non_null(inputs);

    bt_value_map_insert_entry(params, "inputs", inputs);
    bt_value_put_ref(inputs);

    bt_graph_add_component_status st = add_source(s, params, NULL);
    bt_value_put_ref(params);

    assert_int_equal(st, BT_GRAPH_ADD_COMPONENT_STATUS_ERROR);
}

static void test_ftrace_in_initialize_bad_trace_path(void **state)
{
    test_state_t *s = *state;

    bt_value *params = make_params("/nonexistent/path/trace.dat");
    assert_non_null(params);

    bt_graph_add_component_status st = add_source(s, params, NULL);
    bt_value_put_ref(params);

    assert_int_equal(st, BT_GRAPH_ADD_COMPONENT_STATUS_ERROR);
}

static void test_ftrace_get_supported_mip_versions(void **state)
{
    (void)state;
    bt_message_iterator_class *iter_class =
        bt_message_iterator_class_create(ftrace_in_message_iterator_next);

    bt_self_component_class_source *self_component_class =
        (bt_self_component_class_source *)bt_component_class_source_create("test-src-mip", iter_class);
    assert_non_null(self_component_class);

    const bt_value *params = NULL;
    void *initialize_method_data = NULL;
    bt_logging_level logging_level = BT_LOGGING_LEVEL_WARNING;
    bt_integer_range_set_unsigned *const supported_versions =
        bt_integer_range_set_unsigned_create();
    assert_non_null(supported_versions);

    bt_component_class_get_supported_mip_versions_method_status status =
        ftrace_get_supported_mip_versions(self_component_class,
                                          params, initialize_method_data, logging_level,
                                          supported_versions);
    assert_int_equal(status, BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ftrace_in_initialize_null_params,
                                        suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_ftrace_in_initialize_missing_inputs_key,
                                        suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_ftrace_in_initialize_empty_inputs_array,
                                        suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_ftrace_in_initialize_bad_trace_path,
                                        suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_ftrace_get_supported_mip_versions,
                                        test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}