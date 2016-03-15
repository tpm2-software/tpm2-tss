m4_define([tpm20_major_version], [0])
m4_define([tpm20_minor_version], [98])
m4_define([tpm20_version_string], [tpm20_major_version.tpm20_minor_version])

AC_INIT([tpm2.0-tss], [tpm20_version_string])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT()
AX_PTHREAD([], [AC_MSG_ERROR([requires pthread])])
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
AC_CONFIG_FILES([Makefile])
PKG_CHECK_MODULES([CMOCKA],[cmocka])
AC_OUTPUT
