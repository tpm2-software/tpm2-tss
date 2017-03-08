m4_define([tpm20_major_version], [1])
m4_define([tpm20_minor_version], [0])
m4_define([tpm20_version_string], [tpm20_major_version.tpm20_minor_version])

AC_INIT([tpm2.0-tss], [tpm20_version_string])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_CXX
LT_INIT()
AC_C_BIGENDIAN
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

AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-std=gnu99])
AX_ADD_COMPILER_FLAG([-Wformat])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])
AX_ADD_PREPROC_FLAG([-D_FORTIFY_SOURCE=2])
AX_ADD_PREPROC_FLAG([-U_FORTIFY_SOURCE])
AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

AC_OUTPUT
