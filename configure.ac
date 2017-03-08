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

dnl add_compiler_flag:
dnl   A macro to add a CFLAG to the EXTRA_CFLAGS variable. This macro will
dnl   check to be sure the compiler supprts the flag. Flags can be made
dnl   mandatory (configure will fail).
dnl $1: C compiler flag to add to EXTRA_CFLAGS.
dnl $2: Set to "required" to cause configure failure if flag not supported..
AC_DEFUN([add_compiler_flag],[
    AX_CHECK_COMPILE_FLAG([$1],[
        EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],[
        AS_IF([test x$2 != xrequired],[
            AC_MSG_WARN([Optional CFLAG "$1" not supported by your compiler, continuing.])],[
            AC_MSG_ERROR([Required CFLAG "$1" not supported by your compiler, aborting.])]
        )]
    )]
)
dnl add_preproc_flag
dnl
dnl $1: Preprocessor flag to add to EXTRA_CFLAGS.
dnl $2: Set to "required" t ocause configure failure if preprocesor flag
dnl     is not supported.
AC_DEFUN([add_preproc_flag],[
    AX_CHECK_PREPROC_FLAG([$1],[
        EXTRA_CFLAGS="$EXTRA_CFLAGS $1"],[
        AS_IF([test x$2 != xrequired],[
            AC_MSG_WARN([Optional preprocessor flag "$1" not supported by your compiler, continuing.])],[
            AC_MSG_ERROR([Required preprocessor flag "$1" not supported by your compiler, aborting.])]
        )]
    )]
)
dnl add_link_lag:
dnl   A macro to add a LDLAG to the EXTRA_LDFLAGS variable. This macro will
dnl   check to be sure the linker supprts the flag. Flags can be made
dnl   mandatory (configure will fail).
dnl $1: linker flag to add to EXTRA_LDFLAGS.
dnl $2: Set to "required" to cause configure failure if flag not supported.
AC_DEFUN([add_link_flag],[
    AX_CHECK_LINK_FLAG([$1],[
        EXTRA_CFLAGS="$EXTRA_LDFLAGS $1"],[
        AS_IF([test x$2 != xrequired],[
            AC_MSG_WARN([Optional LDFLAG "$1" not supported by your linker, continuing.])],[
            AC_MSG_ERROR([Required LDFLAG "$1" not supported by your linker, aborting.])]
        )]
    )]
)

add_compiler_flag([-Wall])
add_compiler_flag([-Werror])
add_compiler_flag([-Wformat])
add_compiler_flag([-Wformat-security])
add_compiler_flag([-fstack-protector-all])
add_compiler_flag([-fpic])
add_compiler_flag([-fPIC])
add_preproc_flag([-D_FORTIFY_SOURCE=2])
add_preproc_flag([-U_FORTIFY_SOURCE])
add_link_flag([-Wl,--no-undefined])
add_link_flag([-Wl,-z,noexecstack])
add_link_flag([-Wl,-z,now])
add_link_flag([-Wl,-z,relro])

AC_SUBST([EXTRA_CFLAGS])
AC_SUBST([EXTRA_LDFLAGS])

AC_OUTPUT
