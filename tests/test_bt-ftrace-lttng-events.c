/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/bt-ftrace-lttng-events.h"
#include <stdlib.h>

static void test_lttng_get_event_name_from_event(void **state)
{
    struct tep_event *event = calloc(1, sizeof(struct tep_event));
    event->system = "irq";
    event->name = "softirq_mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "irq_softirq_mock");
    event->name = "irq_mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "irq_mock");

    event->system = "timer";
    event->name = "htimer_mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "timer_htimer_mock");
    event->name = "timer_mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "timer_mock");

    event->system = "kmem";
    event->name = "kmalloc";
    assert_string_equal(lttng_get_event_name_from_event(event), "kmem_kmalloc");
    event->name = "kmem_mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "kmem_mock");

    event->system = "console";
    event->name = "mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "console_mock");
    event->name = "console_mock";
    assert_string_equal(lttng_get_event_name_from_event(event), "console_mock");
    free(event);
}

static void test_lttng_get_field_name_from_event(void **state)
{
    struct tep_event *event = calloc(1, sizeof(struct tep_event));;
    const char *field_name;
    event->system = "mock_system";
    event->name = "mock_event";
    field_name = "pid";
    assert_string_equal(lttng_get_field_name_from_event(event, field_name), "tid");
    field_name = "comm";
    assert_string_equal(lttng_get_field_name_from_event(event, field_name), "comm");
    free(event);
}

static void test_lttng_get_field_val_from_event_unsigned(void **state)
{
    struct tep_event *event = calloc(1, sizeof(struct tep_event));
    const char *field_name;
    uint64_t val;
    val = 42;
    assert_int_equal(lttng_get_field_val_from_event_unsigned(event, field_name, val), 42);
    free(event);
}

static void test_lttng_get_field_val_from_event_signed(void **state)
{
    struct tep_event *event = calloc(1, sizeof(struct tep_event));
    const char *field_name = "prio";
    int64_t val;
    event->system = "sched";
    val = 142;
    assert_int_equal(lttng_get_field_val_from_event_signed(event, field_name, val), 42);
    event->system = "irq";
    field_name = "val";
    val = 142;
    assert_int_equal(lttng_get_field_val_from_event_signed(event, field_name, val), 142);
    free(event);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lttng_get_event_name_from_event),
        cmocka_unit_test(test_lttng_get_field_name_from_event),
        cmocka_unit_test(test_lttng_get_field_val_from_event_unsigned),
        cmocka_unit_test(test_lttng_get_field_val_from_event_signed),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
