/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Infineon Technologies AG
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <dirent.h>           // for closedir, dirent, opendir, readdir, DIR
#include <errno.h>            // for errno
#include <inttypes.h>         // for PRIu16, PRIxPTR, PRIdMAX
#include <limits.h>           // for PATH_MAX
#include <signal.h>           // for kill, SIGTERM, SIGHUP, SIGKILL
#include <stdbool.h>          // for false, true, bool
#include <stdio.h>            // for snprintf, asprintf
#include <stdlib.h>           // for NULL, free, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>           // for strerror, strcmp, strdup, strlen, strsep
#include <sys/prctl.h>        // for prctl, PR_SET_PDEATHSIG
#include <sys/random.h>       // for getrandom
#include <sys/stat.h>         // for chmod, S_IRGRP, S_IROTH, S_IRUSR, S_IWUSR
#include <sys/types.h>        // for size_t, pid_t, ssize_t
#include <sys/wait.h>         // for waitpid, WCOREDUMP, WNOHANG
#include <unistd.h>           // for usleep, chdir, execvp, fork, getpid

#include "tcti-common.h"      // for TSS2_TCTI_COMMON_CONTEXT, TCTI_STATE_TR...
#include "tcti-start-sim.h"
#include "tss2_common.h"      // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_TCTI_RC_...
#include "tss2_tcti.h"        // for TSS2_TCTI_CONTEXT, TSS2_TCTI_INFO, TSS2...
#include "tss2_tctildr.h"     // for Tss2_TctiLdr_Finalize, Tss2_TctiLdr_Ini...
#include "tss2_tpm2_types.h"  // for TPM2_RC_SUCCESS
#include "util/aux_util.h"    // for ARRAY_LEN, SAFE_FREE, UNUSED

#define LOGMODULE tcti
#include "util/log.h"         // for LOG_ERROR, LOG_TRACE, LOG_WARNING, LOG_...


#define PORT_MIN 1024
#define PORT_MAX 65534

#define ERROR_INTERNAL -1
#define ERROR_PROCESS_DIED -2
#define ERROR_PROCESS_DIED_MAYBE -3


static int get_mssim_command(char *command, size_t command_len, const char *workdir, uint16_t port) {
    (void) workdir;

    int ret = snprintf(command, command_len, "tpm_server -port %" PRIu16, port);
    if (ret < 0) {
        LOG_ERROR("snprintf failed.");
        return EXIT_FAILURE;
    }
    if (ret == (int) command_len) {
        LOG_ERROR("snprintf failed: output truncated.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int get_swtpm_command(char *command, size_t command_len, const char *workdir, uint16_t port) {
    int ret = snprintf(command, command_len, "swtpm socket --tpm2 -p %" PRIu16 " --ctrl type=tcp,port=%" PRIu16 " --log fd=1,level=5 --flags not-need-init --tpmstate dir=%s --locality allow-set-locality", port, port + 1, workdir);
    if (ret < 0) {
        LOG_ERROR("snprintf failed.");
        return EXIT_FAILURE;
    }
    if (ret == (int) command_len) {
        LOG_ERROR("snprintf failed: output truncated.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/* Encapsulates all the const data we have to know about the different simulator variants */
#define TCTI_SIM_VARIANT_IDX_MSSIM 0
#define TCTI_SIM_VARIANT_IDX_SWTPM 1
static const tcti_sim_variant tcti_sim_variants[] = {
    {
        .name = "mssim",
        .name_len = sizeof(tcti_sim_variant[0]) - 1,
        .get_command_fn = get_mssim_command,
        .num_ports = 4,
    },
    {
        .name = "swtpm",
        .name_len = sizeof(tcti_sim_variant[1]) - 1,
        .get_command_fn = get_swtpm_command,
        .num_ports = 2,
    },
};

/*
 * Split string into array of words.
 * Allocates memory which must be freed using split_string_free().
 * Adds an additional NULL at the end.
 */
static int split_string_alloc(char **dest[], size_t *dest_len, const char *src, const char delimiter) {
    char *src_cpy;
    char *token;
    const char delimiter_str[] = { delimiter, '\0' };

    /* Get number of elements, start counting at one because we always have one element more than delimiters */
    *dest_len = 1;
    for (size_t i = 0; i < strlen(src); i++) {
        if (src[i] == delimiter) {
            (*dest_len)++;
        }
    }

    /* Add one since an additional element NULL is added */
    (*dest_len)++;

    /* Allocate array for string elements */
    *dest = malloc(sizeof(char *) * (*dest_len));
    if (dest == NULL) {
        return EXIT_FAILURE;
    }

    /* Copy input since strsep() mutates the string */
    src_cpy = strdup(src);
    if (src_cpy == NULL) {
        free(*dest);
        return EXIT_FAILURE;
    }

    /* Jump to each string element, replacing the delimiters with '\0' */
    *dest_len = 0;
    while ((token = strsep(&src_cpy, delimiter_str))) {
        (*dest)[(*dest_len)++] = token;
    }

    /* Add last element NULL */
    (*dest)[(*dest_len)++] = NULL;

    return EXIT_SUCCESS;
}

static void split_string_free(char *dest[]) {
    /* free memory from strdup() */
    free(dest[0]);
    /* free array of elements */
    free(dest);
}

static int simulator_make_workdir(char *tempdir_template) {
    int ret;
    char *tempdir;

    /* create temporary directory */
    tempdir = mkdtemp(tempdir_template);
    if (tempdir == NULL) {
        LOG_ERROR("mkdtemp failed for %s: %s", tempdir_template, strerror(errno));
        return EXIT_FAILURE;
    }
    ret = chmod(tempdir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (ret != 0) {
        LOG_ERROR("chmod failed for %s: %s", tempdir, strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int simulator_execute_blocking(pid_t parent_pid, const char *workdir, char * const argv[]) {
    int ret;

    LOG_DEBUG("TPM simulator process: changing directory: %s", workdir);
    ret = chdir(workdir);
    if (ret != 0) {
        LOG_ERROR("chmod failed for %s: %s", workdir, strerror(errno));
        return EXIT_FAILURE;
    }

    /* ask kernel to kill this child process when parent dies */
    ret = prctl(PR_SET_PDEATHSIG, SIGHUP);
    if (ret == -1) {
        LOG_ERROR("TPM simulator process error: prctl failed: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    /* double-check that parent did not die before we could set PR_SET_PDEATHSIG */
    if (getppid() != parent_pid) {
        LOG_ERROR("TPM simulator process error: parent died early.");
        return EXIT_FAILURE;
    }

    ret = execvp(argv[0], argv);
    if (ret == -1) {
        LOG_ERROR("TPM simulator process error: execvp(%s) failed: %s", argv[0], strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/* On success, return 0..n, on error, return ERROR_INTERNAL or ERROR_PROCESS_DIED_MAYBE. */
static int simulator_get_num_sockets(pid_t pid) {
    int ret, ret2;
    char fd_dir_path[PATH_MAX];
    DIR *dir;
    struct dirent *entry;
    char fd_link_path[PATH_MAX];
    char fd_dest_path[PATH_MAX];
    ssize_t len;
    const char *socket_prefix = "socket:[";
    size_t socket_prefix_strlen = strlen(socket_prefix);
    long inode;
    uint16_t num_sockets = 0;

    LOG_TRACE("Determining number of sockets");

    ret = snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%" PRIdMAX "/fd", (intmax_t) pid);
    if (ret < 0) {
        LOG_ERROR("snprintf failed.");
        return ERROR_INTERNAL;
    }
    if (ret == sizeof(fd_dir_path)) {
        LOG_ERROR("snprintf failed: output truncated.");
        return ERROR_INTERNAL;
    }

    dir = opendir(fd_dir_path);
    if (dir == NULL) {
        /* maybe our process died */
        LOG_WARNING("opendir(%s) failed: %s", fd_dir_path, strerror(errno));
        return ERROR_PROCESS_DIED_MAYBE;
    }

    /* iterate over /proc/<pid>/fd/... */
    while (1) {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL) {
            if (errno != 0) {
                /* maybe our process died */
                LOG_WARNING("readdir failed: %s", strerror(errno));
                ret = ERROR_PROCESS_DIED_MAYBE;
                goto cleanup_opendir;
            }

            /* no more directory entries */
            break;
        }

        /* skip entries . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* construct file name for file in /proc/<pid>/fd/ */
        ret = snprintf(fd_link_path, sizeof(fd_link_path), "%s/%s", fd_dir_path, entry->d_name);
        if (ret < 0) {
            LOG_ERROR("snprintf failed");
            ret = ERROR_INTERNAL;
            goto cleanup_opendir;
        }
        if (ret == sizeof(fd_dir_path)) {
            LOG_ERROR("snprintf failed: output truncated.");
            ret = ERROR_INTERNAL;
            goto cleanup_opendir;
        }

        /* file is a symlink, read destination path (might be "socket:[<inode>]") */
        len = readlink(fd_link_path, fd_dest_path, sizeof(fd_dest_path) - 1);
        if (len == -1) {
            LOG_WARNING("readlink failed for %s: %s", fd_link_path, strerror(errno));
            ret = ERROR_PROCESS_DIED_MAYBE;
            goto cleanup_opendir;
        }
        /* readlink does not null-terminate fd_dest_path, fix that */
        fd_dest_path[len++] = '\0';

        /* check if symlink points to socket (i.e. starts with socket_prefix), if not skip */
        if (strncmp(fd_dest_path, socket_prefix, socket_prefix_strlen) != 0) {
            continue;
        }

        errno = 0;
        inode = strtol(fd_dest_path + socket_prefix_strlen, NULL, 10);
        if (errno != 0) {
            LOG_ERROR("strtol failed: %s", strerror(errno));
            ret = ERROR_INTERNAL;
            goto cleanup_opendir;
        }

        UNUSED(inode);  /* in case LOG_TRACE() is compiled out */
        LOG_TRACE("Found socket (inode=%ld)", inode);
        num_sockets++;
    }

    ret = EXIT_SUCCESS;

cleanup_opendir:
    ret2 = closedir(dir);
    if (ret2 != 0) {
        LOG_ERROR("closedir failed: %s", strerror(errno));
    }

    if (ret != EXIT_SUCCESS) {
        /* error */
        return ret;
    }

    LOG_TRACE("Number of sockets: %d", num_sockets);
    return num_sockets;
}

static int simulator_check_alive(pid_t child_pid) {
    /* we are the parent, child is pid */

    int status;
    int r = waitpid(child_pid, &status, WNOHANG);
    if (r < 0) {
        LOG_ERROR("waitpid failed. Did TPM simulator with PID %d die?", child_pid);
        return EXIT_FAILURE;
    } else if (r == child_pid && WIFEXITED(status)) {
        LOG_DEBUG("TPM simulator exited: %d", WEXITSTATUS(status));
        return WEXITSTATUS(status);
    } else if (r == child_pid && WIFSIGNALED(status)) {
        LOG_DEBUG("TPM simulator terminated by signal: %d", WTERMSIG(status));
#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            LOG_WARNING("TPM simulator: Core dumped.");
        }
        return EXIT_FAILURE;
#endif
    /*
    * Only relevant for waitpid(pid, WUNTRACED) for resuming the parent after child was stopped via SIGSTOP
    *  } else if (r == pid && WIFSTOPPED(status)) {
    *      printf("Stopped by signal: %d\n", WSTOPSIG(status));
    *  } else if (r == pid && WIFCONTINUED(status)) {
    *      printf("continued\n");
    */
    } else {
        LOG_TRACE("TPM simulator with PID %d is still alive.", child_pid);
    }

    return EXIT_SUCCESS;
}

/* Returns zero on success, ERROR_INTERNAL for a not recoverable error or
 * ERROR_RPOCESS_DIED when the process ended unexpectedly (e.g. on a port
 * conflict).
 */
static int simulator_start_and_wait_for_ports(pid_t *simulator_pid, const tcti_sim_variant *variant, uint16_t port) {
    int r;
    int num_sockets;
    char command[PATH_MAX];
    char workdir[] = "/tmp/tcti-start-sim-XXXXXX";
    char **argv;
    size_t argc;

    /* create simulator workdir to a temporary directory to deal with state files */
    r = simulator_make_workdir(workdir);
    if (r != EXIT_SUCCESS) {
        return ERROR_INTERNAL;
    }

    /* get command to execute simulator as single string with spaces */
    r = variant->get_command_fn(command, sizeof(command), workdir, port);
    if (r != EXIT_SUCCESS) {
        return ERROR_INTERNAL;
    }
    LOG_DEBUG("Starting TPM simulator: %s", command);

    /* split command into argv array */
    r = split_string_alloc(&argv, &argc, command, ' ');
    if (r != EXIT_SUCCESS) {
        return ERROR_INTERNAL;
    }

    pid_t parent_pid = getpid();
    pid_t child_pid = fork();
    if (child_pid == -1) {
        LOG_ERROR("fork failed: %s", strerror(errno));
        r = ERROR_INTERNAL;
        goto cleanup;
    }
    if (child_pid == 0) {
        /* we are the child and will be the simulator process */

        simulator_execute_blocking(parent_pid, workdir, argv);
        /* no error handling, we only reach here on error */

        split_string_free(argv);

        exit(EXIT_FAILURE);
    }

    /* we are the parent */
    *simulator_pid = child_pid;
    LOG_TRACE("Proces with TCTI has PID %d", parent_pid);
    LOG_TRACE("TPM simulator has PID %d", *simulator_pid);

    /* busy wait until ports are open */
    for (int process_died_maybe_retry = 0; process_died_maybe_retry < 3;) {
        r = simulator_check_alive(*simulator_pid);
        if (r != EXIT_SUCCESS) {
            /* tpm sim died unexpectedly, maybe due to a port conflict */
            r = ERROR_PROCESS_DIED;
            goto cleanup;
        }

        num_sockets = simulator_get_num_sockets(*simulator_pid);
        if (num_sockets == ERROR_PROCESS_DIED_MAYBE) {
            /* error while trying to determine sockets, process might have died */
            process_died_maybe_retry++;
        } else if (num_sockets < 0) {
            /* fatal error */
            r = ERROR_INTERNAL;
            goto cleanup;
        } else if (num_sockets >= variant->num_ports) {
            /* success */
            r = EXIT_SUCCESS;
            goto cleanup;
        }
        /* we got ERROR_PROCESS_DIED_MAYBE */

        /* wait 10ms */
        r = usleep(10000);
        if (r < 0) {
            LOG_ERROR("usleep failed: %s", strerror(errno));
        }
    }

    r = ERROR_PROCESS_DIED;

cleanup:
    split_string_free(argv);

    return r;
}

static int simulator_kill(pid_t simulator_pid) {
    int ret;
    int status;
    int signals[] = { SIGTERM, SIGKILL };
    const char *signal_names[] = { str(SIGTERM), str(SIGKILL) };

    /* try to kill simulator; ask nicely first (SIGTERM), then with more insistence (SIGKILL) */
    for (size_t i = 0; i < ARRAY_LEN(signals); i++) {
        LOG_TRACE("Sending kill(%s=%d) to TPM simulator with PID %d", signal_names[i], signals[i], simulator_pid);

        ret = kill(simulator_pid, SIGTERM);
        if (ret == -1) {
            UNUSED(signal_names);  /* in case LOG_TRACE() is compiled out */
            LOG_WARNING("kill(%s=%d) of TPM simulator failed: %s", signal_names[i], signals[i], strerror(errno));
            /* sleep and try again in next iteration */
        }

        /*
         * wait for TPM simulator to actually terminate.
         * we will escalate to next signal after 20*10ms = 200ms
         */
        for (int j = 0; j < 20; j++) {
            ret = waitpid(simulator_pid, &status, WNOHANG);
            if (ret < 0) {
                LOG_ERROR("waitpid failed. Did TPM simulator with PID %d die?", simulator_pid);
                /* sleep and try again in next iteration */
            } else if (ret == simulator_pid && WIFEXITED(status)) {
                LOG_DEBUG("TPM simulator exited on its own: %d", WEXITSTATUS(status));
                return EXIT_SUCCESS;
            } else if (ret == simulator_pid && WIFSIGNALED(status)) {
                LOG_DEBUG("TPM simulator terminated by signal: %d", WTERMSIG(status));
        #ifdef WCOREDUMP
                if (WCOREDUMP(status)) {
                    LOG_WARNING("TPM simulator: Core dumped.");
                }
        #endif
                return EXIT_SUCCESS;
            /*
            * Only relevant for waitpid(pid, WUNTRACED) for resuming the parent after child was stopped via SIGSTOP
            *  } else if (r == pid && WIFSTOPPED(status)) {
            *      printf("Stopped by signal: %d\n", WSTOPSIG(status));
            *  } else if (r == pid && WIFCONTINUED(status)) {
            *      printf("continued\n");
            */
            } else {
                LOG_TRACE("TPM simulator with PID %d is still alive.", simulator_pid);
            }

            usleep(10000);
        }

        usleep(50000);
    }

    /*
     * Even if we could not kill the child, it will be killed via PR_SET_PDEATHSIG
     * when the parent dies at the latest.
     */

    return EXIT_FAILURE;
}

static int get_random_port() {
    uint8_t buf[2];
    ssize_t ret = -1;
    uint16_t rand;

    while (ret < 0) {
        ret = getrandom(buf, ARRAY_LEN(buf), 0);
        if (ret == -1) {
            LOG_WARNING("getrandom failed: %s", strerror(errno));
        }
    }
    rand = buf[1] << 8 | buf[0];

    return PORT_MIN + rand % (PORT_MAX - PORT_MIN);
}

/*
 * Search for first occurance of known TPM simulator tctis (mssim, swtpm) in
 * conf string and choose simulator variant based on that. If a port is passed
 * to mssim/swtpm in its conf, parse that, too.
 *
 * If no known tcti could be found, return error.
 * If no port could be found, a random one is used.
 *
 */
static TSS2_RC
tcti_start_sim_conf_parse_alloc(const char *conf, const tcti_sim_variant **variant, uint16_t *port, char **new_conf)
{
    int ret;
    TSS2_RC rc;
    char *conf_cpy;
    char *conf_cpy_tmp;
    char *element;
    bool is_simulator_tcti_name;
    bool was_simulator_tcti_conf_parsed = false;
    const char *port_prefix = "port=";
    size_t port_prefix_strlen = strlen(port_prefix);
    const char *port_substring;

    *new_conf = NULL;

    /*
     * Bear with me here.
     *
     * This is complex for two reasons. Firstly, we need to do string parsing in
     * C. I'm yearning for Rust right now, but oh well - we'll get there
     * eventually.
     *
     * Secondly, we need to be able to deal with various config strings - and if
     * no port was given even manipulate the config string.
     *
     * Allowed:
     *  - mssim:host=localhost,port=2321
     *  - swtpm:host=localhost,port=2321
     *  - pcap:mssim:host=localhost
     *  - pcap:mssim
     *  - mssim
     *
     * Not allowed
     *  - ""
     *  - device
     *  - mssim:foo:bar
     *
     * Rules:
     *  - A valid config string can contain 0..n colons, they split the string
     *    into elements
     *  - We search for the first element which starts with a known tcti
     *    simulator tcti name ("mssim", "swtpm")
     *  - This simulator tcti name element can be followed by an optional
     *    simulator tcti config element (e.g. "host=localhost,port=2321")
     *  - After this, no further element is allowed
     *  - If there is no simulator tcti config element, a random port is chosen
     *    and a config is appended (e.g. ":port=12345")
     *  - If a there is a simulator tcti config element which does not specify a
     *    port, a random port is chosen and a key-value-pair is appended (e.g.
     *    ",port=12345")
     *
     * Most of this should be moved to a common config string
     * parsing/manipulation library for all tctis, preferably in Rust.
     */

    /* Copy input since strsep() mutates the string */
    conf_cpy = strdup(conf);
    if (conf_cpy == NULL) {
        return TSS2_TCTI_RC_MEMORY;
    }
    conf_cpy_tmp = conf_cpy;

    *variant = NULL;
    *port = 0;
    was_simulator_tcti_conf_parsed = false;

    /* For each element (separated by ':' which will be replaced with '\0') */
    while ((element = strsep(&conf_cpy_tmp, ":"))) {
        is_simulator_tcti_name = false;

        /* For each known simulator tcti name */
        for (size_t i = 0; i < ARRAY_LEN(tcti_sim_variants); i++) {
            if (strcmp(element, tcti_sim_variants[i].name) == 0) {
                is_simulator_tcti_name = true;
                *variant = &tcti_sim_variants[i];
                break;
            }
        }

        if (is_simulator_tcti_name) {
            continue;
        }

        if (*variant == NULL) {
            /* simulator tcti name not found, continue searching */
            continue;
        }

        /* simulator tcti name is found */

        if (was_simulator_tcti_conf_parsed) {
            /* simulator tcti conf is also found, that means this element is an
             * excess element
             */
            rc = TSS2_TCTI_RC_BAD_VALUE;
            goto cleanup;
        }

        /* this element is the simulator tcti conf, parse port if given */
        /* parse port if given (first occurance of "port=")*/
        port_substring = strstr(element, port_prefix);
        if (port_substring == NULL) {
            /* no port found */
            *port = 0;
            was_simulator_tcti_conf_parsed = true;
            continue;
        }

        errno = 0;
        *port = strtoul(port_substring + port_prefix_strlen, NULL, 10);
        if (errno != 0) {
            LOG_ERROR("strtoul failed: %s", strerror(errno));
            rc = TSS2_TCTI_RC_GENERAL_FAILURE;
            goto cleanup;
        }
        LOG_TRACE("Found TPM simulator port: %" PRIu16, *port);

        was_simulator_tcti_conf_parsed = true;
    }

    if (*variant == NULL) {
        LOG_ERROR("Unknown child TCTI: %s", conf);
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto cleanup;
    }

    if (*port == 0) {
        *port = get_random_port();

        /* port was chosen randomly, add key-value-pair to child conf */
        if (was_simulator_tcti_conf_parsed) {
            ret = asprintf(new_conf, "%s,port=%" PRIu16, conf, *port);
        } else {
            ret = asprintf(new_conf, "%s:port=%" PRIu16, conf, *port);
        }
        if (ret == -1) {
            LOG_ERROR("asprintf failed.");
            rc = TSS2_TCTI_RC_MEMORY;
            goto cleanup;
        }
    } else {
        /* port was specified, no changes to tcti_child_conf */
        *new_conf = strdup(conf);
        if (*new_conf == NULL) {
            LOG_ERROR("strdup failed.");
            rc = TSS2_TCTI_RC_MEMORY;
            goto cleanup;
        }
    }

    rc = TSS2_RC_SUCCESS;

cleanup:
    free(conf_cpy);

    return rc;
}

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the pcap TCTI context. The only safeguard we have to ensure this
 * operation is possible is the magic number in the pcap TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
static TSS2_TCTI_START_SIM_CONTEXT*
tcti_start_sim_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC (tcti_ctx) == TCTI_START_SIM_MAGIC) {
        return (TSS2_TCTI_START_SIM_CONTEXT*)tcti_ctx;
    }
    return NULL;
}

/*
 * This function down-casts the pcap TCTI context to the common context
 * defined in the tcti-common module.
 */
static TSS2_TCTI_COMMON_CONTEXT*
tcti_start_sim_down_cast (TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim)
{
    if (tcti_start_sim == NULL) {
        return NULL;
    }
    return &tcti_start_sim->common;
}

TSS2_RC
tcti_start_sim_transmit (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t size,
    const uint8_t *cmd_buf)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = tcti_start_sim_context_cast (tcti_ctx);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_start_sim_down_cast (tcti_start_sim);
    TSS2_RC rc;

    if (tcti_start_sim == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_transmit_checks (tcti_common, cmd_buf, TCTI_START_SIM_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    LOGBLOB_DEBUG (cmd_buf, size, "sending %zu byte command buffer:", size);

    rc = Tss2_Tcti_Transmit (tcti_start_sim->tcti_child, size, cmd_buf);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Failed calling TCTI transmit of child TCTI module");
        return rc;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_start_sim_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    unsigned char *response_buffer,
    int32_t timeout)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = tcti_start_sim_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_start_sim_down_cast (tcti_start_sim);
    TSS2_RC rc;

    if (tcti_start_sim == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_receive_checks (tcti_common, response_size, TCTI_START_SIM_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tss2_Tcti_Receive (tcti_start_sim->tcti_child,
                            response_size, response_buffer,
                            timeout);
    if (rc != TPM2_RC_SUCCESS) {
        return rc;
    }

    /* partial read */
    if (response_buffer == NULL) {
        return rc;
    }

    LOGBLOB_DEBUG (response_buffer, *response_size, "Response Received");

    tcti_common->state = TCTI_STATE_TRANSMIT;
    return rc;
}

TSS2_RC
tcti_start_sim_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = tcti_start_sim_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_start_sim_down_cast (tcti_start_sim);
    TSS2_RC rc;

    if (tcti_start_sim == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_cancel_checks (tcti_common, TCTI_START_SIM_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    LOG_WARNING ("Logging Tcti_Cancel to a PCAP file is not implemented");

    rc = Tss2_Tcti_Cancel (tcti_start_sim->tcti_child);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->state = TCTI_STATE_TRANSMIT;
    return rc;
}

TSS2_RC
tcti_start_sim_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = tcti_start_sim_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_start_sim_down_cast (tcti_start_sim);
    TSS2_RC rc;

    if (tcti_start_sim == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    rc = tcti_common_set_locality_checks (tcti_common, TCTI_START_SIM_MAGIC);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    rc = Tss2_Tcti_SetLocality (tcti_start_sim->tcti_child, locality);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->locality = locality;
    return rc;
}

TSS2_RC
tcti_start_sim_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = tcti_start_sim_context_cast (tctiContext);

    if (tcti_start_sim == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    return Tss2_Tcti_GetPollHandles (tcti_start_sim->tcti_child, handles,
                                     num_handles);
}

void
tcti_start_sim_finalize (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = tcti_start_sim_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_start_sim_down_cast (tcti_start_sim);

    if (tcti_start_sim == NULL) {
        return;
    }

    Tss2_TctiLdr_Finalize (&tcti_start_sim->tcti_child);

    SAFE_FREE(tcti_start_sim->tcti_child_name_conf);

    /* we cannot recover from a failed kill. ignore return code */
    simulator_kill(tcti_start_sim->simulator_pid);

    tcti_common->state = TCTI_STATE_FINAL;
}

/*
 * This is an implementation of the standard TCTI initialization function for
 * this module.
 */
TSS2_RC
Tss2_Tcti_Start_Sim_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    TSS2_TCTI_START_SIM_CONTEXT *tcti_start_sim = (TSS2_TCTI_START_SIM_CONTEXT*) tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_start_sim_down_cast (tcti_start_sim);
    TSS2_RC rc = TSS2_RC_SUCCESS;
    int ret;

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_START_SIM_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s",
               (uintptr_t)tctiContext, (uintptr_t)size, conf);

    tcti_start_sim->tcti_child_name_conf = NULL;

    /* retry loop for loading child tcti and connecting to simulator */
    for (int i = 0; i < 3; i++) {
        /* retry loop for starting simulator and checking open ports */
        for (int j = 0; j < 10; j++) {
            SAFE_FREE(tcti_start_sim->tcti_child_name_conf);
            rc = tcti_start_sim_conf_parse_alloc(conf, &tcti_start_sim->variant, &tcti_start_sim->port, &tcti_start_sim->tcti_child_name_conf);
            if (rc != TSS2_RC_SUCCESS) {
                return TSS2_TCTI_RC_BAD_VALUE;
            }

            ret = simulator_start_and_wait_for_ports(&tcti_start_sim->simulator_pid, tcti_start_sim->variant, tcti_start_sim->port);
            if (ret == EXIT_SUCCESS) {
                break;
            } else if (ret == ERROR_PROCESS_DIED) {
                LOG_WARNING("Starting TPM Simulator failed, maybe due to a port conflict.");
                /* retry */
            } else {
                /* error where process did not die */
                rc = TSS2_TCTI_RC_IO_ERROR;
                goto exit_with_kill;
            }

            LOG_DEBUG("Retry starting simulator.");
        }

        if (ret != EXIT_SUCCESS) {
            /* retries ran out */
            rc = TSS2_TCTI_RC_IO_ERROR;
            goto exit_without_kill;
        }

        if (tcti_start_sim->variant == &tcti_sim_variants[TCTI_SIM_VARIANT_IDX_MSSIM]) {
            /* mssim might not be ready yet due to manufacturing steps, wait 100ms */
            usleep(100000);
        }

        rc = Tss2_TctiLdr_Initialize (tcti_start_sim->tcti_child_name_conf, &tcti_start_sim->tcti_child);
        if (rc != TSS2_RC_SUCCESS) {
            /* quite seldom the TPM Simulator dies just before we want to connect */
            LOG_WARNING ("Error loading TCTI: %s. Maybe TPM Simulator died?", conf);
            /* retry */
        } else {
            break;
        }

        LOG_DEBUG("Retry connecting to simulator.");
    }

    if (ret != EXIT_SUCCESS) {
        /* retries ran out */
        rc = TSS2_TCTI_RC_IO_ERROR;
        goto exit_with_kill;
    }

    TSS2_TCTI_MAGIC (tcti_common) = TCTI_START_SIM_MAGIC;
    TSS2_TCTI_VERSION (tcti_common) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_common) = tcti_start_sim_transmit;
    TSS2_TCTI_RECEIVE (tcti_common) = tcti_start_sim_receive;
    TSS2_TCTI_FINALIZE (tcti_common) = tcti_start_sim_finalize;
    TSS2_TCTI_CANCEL (tcti_common) = tcti_start_sim_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_common) = tcti_start_sim_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_common) = tcti_start_sim_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_common) = tcti_make_sticky_not_implemented;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->locality = 3;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));

    return TSS2_RC_SUCCESS;

exit_with_kill:
    /* we cannot recover from a failed kill. ignore return code */
    simulator_kill(tcti_start_sim->simulator_pid);

exit_without_kill:
    SAFE_FREE(tcti_start_sim->tcti_child_name_conf);

    return rc;
}

/* public info structure */
const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-start-sim",
    .description = "TCTI module for starting a TPM simulator process.",
    .config_help = "The child tcti module and its config string: <name>:<conf>",
    .init = Tss2_Tcti_Start_Sim_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
