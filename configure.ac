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

dnl add_cflag:
dnl   A macro to add a CFLAG to the EXTRA_CFLAGS variable. This macro will
dnl   check to be sure the compiler supprts the flag. Flags can be made
dnl   mandatory (configure will fail).
dnl $1: C compiler flag to add to EXTRA_CFLAGS.
dnl $2: Set to "required" to cause configure failure if flag not supported..
AC_DEFUN([add_cflag],[
    AX_CHECK_COMPILE_FLAG([$1],[
        EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],[
        AS_IF([test x$2 != xrequired],[
            AC_MSG_WARN([Optional CFLAG "$1" not supported by your compiler, continuing.])],[
            AC_MSG_ERROR([Required CFLAG "$1" not supported by your compiler, aborting.])]
        )]
    )]
)
dnl add_ldlag:
dnl   A macro to add a LDLAG to the EXTRA_LDFLAGS variable. This macro will
dnl   check to be sure the linker supprts the flag. Flags can be made
dnl   mandatory (configure will fail).
dnl $1: linker flag to add to EXTRA_LDFLAGS.
dnl $2: Set to "required" to cause configure failure if flag not supported.
AC_DEFUN([add_ldflag],[
    AX_CHECK_LINK_FLAG([$1],[
        EXTRA_CFLAGS="$EXTRA_LDFLAGS $1"],[
        AS_IF([test x$2 != xrequired],[
            AC_MSG_WARN([Optional LDFLAG "$1" not supported by your linker, continuing.])],[
            AC_MSG_ERROR([Required LDFLAG "$1" not supported by your linker, aborting.])]
        )]
    )]
)

add_cflag([-Wall])
add_cflag([-Werror])
add_cflag([-std=gnu99])
add_cflag([-Wformat])
add_cflag([-Wformat-security])
add_cflag([-fstack-protector-all])
add_cflag([-fpic])
add_cflag([-fPIC])
add_ldflag([-Wl,--no-undefined])
add_ldflag([-Wl,-z,noexecstack])
add_ldflag([-Wl,-z,now])
add_ldflag([-Wl,-z,relro])

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

AC_OUTPUT
