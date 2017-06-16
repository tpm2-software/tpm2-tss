AC_INIT([tpm2.0-tss],
        [m4_esyscmd_s([git describe --tags --always --dirty])])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT()
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
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
AC_OUTPUT
