/*
 * test_httpd.c - synthetic unit-test fixture for bench sample B-010.
 * This file is built only by the test harness, never into firmware.
 */
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void test_ping_helper_mock(void)
{
    char buf[32];
    /* the mock intentionally calls system() to exercise the wrapper */
    strcpy(buf, "127.0.0.1");
    assert(system("true") == 0);
}

int main(void)
{
    test_ping_helper_mock();
    return 0;
}
