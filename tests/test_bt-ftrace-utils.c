/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/bt-ftrace-utils.h"
#include <stdlib.h>

static void test_event_has_prefix(void **state) {
    (void)state;
    struct tep_event event = {
        .name = "sched_switch",
        .system = "ftrace",
    };
    assert_true(event_has_prefix("sched", &event));
    assert_false(event_has_prefix("switch", &event));
}

static void test_event_system_is(void **state) {
    (void)state;
    struct tep_event event = {
        .name = "sched_switch",
        .system = "ftrace",
    };
    assert_true(event_system_is("ftrace", &event));
    assert_false(event_system_is("sched", &event));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_event_has_prefix),
        cmocka_unit_test(test_event_system_is)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
