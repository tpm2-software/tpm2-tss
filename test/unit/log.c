/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2019, Infineon Technologies AG
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdio.h>     // for NULL
#include <stdlib.h>    // for setenv

#include "../helper/cmocka_all.h"    // for CMUnitTest, cmocka_run_group_tests, cmocka_uni...

#define LOGMODULE test
#include "util/log.h"  // for LOG_INFO, LOGLEVEL_UNDEFINED, LOGMODULE_status


static void
execute_doLog(char *env_log_level){
    setenv("TSS2_LOG", env_log_level, 1);
    LOG_DEBUG("test");
    LOG_TRACE("test");
    LOG_INFO("test");
    LOG_WARNING("test");
    LOG_INFO("test");
    /* reset log level for next test */
    LOGMODULE_status = LOGLEVEL_UNDEFINED;
}

static void
doLog_test (void **state)
{
    execute_doLog("ALL+none");
    execute_doLog("ALL+unused");
    execute_doLog("ALL+error");
    execute_doLog("ALL+warning");
    execute_doLog("ALL+info");
    execute_doLog("ALL+debug");
    execute_doLog("ALL+trace");
    execute_doLog("ALL+xxxxx");
    execute_doLog("marshal+xxxxx");
    execute_doLog("marshal+debug");
    execute_doLog("test+debug");
    execute_doLog("test+xxxx");
    execute_doLog("ukn+xxxx");
    execute_doLog("test+xxxx");
    execute_doLog("TEST+trace");
    execute_doLog("ALL+xxxxx,mashal+xxxx,tcti+DEBug");
    execute_doLog("ALL+none,mashal+WARNING,tcti+DEBug");
}

int
main (int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (doLog_test),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
