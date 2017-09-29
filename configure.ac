AC_INIT([tpm2-tss],
        [m4_esyscmd_s([git describe --tags --always --dirty])])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT()
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
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
                         [cmocka],
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
AX_ADD_COMPILER_FLAG([-Wno-int-in-bool-context])
AX_ADD_COMPILER_FLAG([-Wno-extern-c-compat])
AX_ADD_COMPILER_FLAG([-Wformat])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])
AX_ADD_PREPROC_FLAG([-U_FORTIFY_SOURCE])
AX_ADD_PREPROC_FLAG([-D_FORTIFY_SOURCE=2])
AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

AC_OUTPUT
