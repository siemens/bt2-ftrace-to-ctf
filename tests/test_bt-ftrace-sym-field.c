/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/bt-ftrace-sym-field.h"
#include <stdlib.h>

static void test_event_field_is_symbolic(void **state)
{
    struct tep_event *event = calloc(1, sizeof(struct tep_event));
    const char *name = "func";
    event->system = "mock_system";
    event->name = "mock_event";
    assert_int_equal(event_field_is_symbolic(event, name), 0);
    event->system = "ftrace";
    event->name = "mock_event";
    assert_int_equal(event_field_is_symbolic(event, name), 0);
    event->system = "ftrace";
    event->name = "funcgraph_mock_event";
    assert_int_equal(event_field_is_symbolic(event, name), 1);
    event->system = "ftrace";
    event->name = "funcgraph_mock_event";
    name = "mock";
    assert_int_equal(event_field_is_symbolic(event, name), 0);
    free(event);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_event_field_is_symbolic),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
