#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/bt-ftrace-source-query.h"
#include "../src/bt-ftrace-source.h"
#include <stdlib.h>

static void test_ftrace_query_method(void **state)
{
    (void)state;
      bt_message_iterator_class *iter_class =
        bt_message_iterator_class_create(ftrace_in_message_iterator_next);

    bt_self_component_class_source *self_component_class =
        (bt_self_component_class_source *)bt_component_class_source_create("test-src-mip", iter_class);
    assert_non_null(self_component_class);

    const char *object_name = "test-object";
    const bt_value *params = NULL;
    void *method_data = NULL;
    const bt_value *result = NULL;

    bt_component_class_query_method_status status =
        ftrace_query_method(self_component_class, NULL, object_name, params, method_data, &result);
    assert_int_equal(status, BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ftrace_query_method)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}