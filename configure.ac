AC_INIT([tpm2-tss],
        [2.0.0-dev],
        [https://github.com/01org/tpm2-tss/issues],
        [],
        [https://github.com/01org/tpm2-tss])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
LT_INIT()
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])]) #Backward compatible setting of "silent-rules"

AC_CONFIG_FILES([Makefile])

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

AC_ARG_ENABLE([unit],
            [AS_HELP_STRING([--enable-unit],
                            [build cmocka unit tests (default is no)])],
            [enable_unit=$enableval],
            [enable_unit=no])
AS_IF([test "x$enable_unit" != xno],
      [PKG_CHECK_MODULES([CMOCKA],
                         [cmocka >= 1.0],
                         [AC_DEFINE([HAVE_CMOCKA],
                                    [1])])])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" != xno])
#
# simulator binary
#
AC_MSG_CHECKING([Checking for simulator binary: $with_simulatorbin])
AC_ARG_WITH([simulatorbin],
            [AS_HELP_STRING([--with-simulatorbin=tpm_server],[simulator executable])],
            [AS_IF([test \( -f "$with_simulatorbin" \) -a \( -x "$with_simulatorbin" \)],
                   [AC_MSG_RESULT([success])
                    AC_SUBST([SIMULATOR_BIN],[$with_simulatorbin])
                    AX_NORMALIZE_PATH([with_simulatorbin])
                    with_simulatorbin_set=yes],
                   [AC_MSG_ERROR([TPM simulator binary provided does not exist])])],
            [with_simulatorbin_set=no])
AM_CONDITIONAL([SIMULATOR_BIN],[test "x$with_simulatorbin_set" = "xyes"])

AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-std=gnu99])
AX_ADD_COMPILER_FLAG([-Wformat])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
                            [build with debug info (default is no)])],
            [enable_debug=$enableval],
            [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], AX_ADD_COMPILER_FLAG([-ggdb3 -O0]))
AS_IF([test "x$enable_debug" = "xno"], [AX_ADD_PREPROC_FLAG([-U_FORTIFY_SOURCE])
                                        AX_ADD_PREPROC_FLAG([-D_FORTIFY_SOURCE=2])])
AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

AX_CODE_COVERAGE

AC_OUTPUT
