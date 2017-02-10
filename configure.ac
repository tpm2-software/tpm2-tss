m4_define([tpm20_major_version], [1])
m4_define([tpm20_minor_version], [0])
m4_define([tpm20_version_string], [tpm20_major_version.tpm20_minor_version])

AC_INIT([tpm2.0-tss], [tpm20_version_string])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT()
AC_C_BIGENDIAN
AC_CHECK_HEADER(endian.h, [AC_DEFINE(HAVE_ENDIAN_H, 1, [endian.h header])])
AX_PTHREAD([], [AC_MSG_ERROR([requires pthread])])
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
