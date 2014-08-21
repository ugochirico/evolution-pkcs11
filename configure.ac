#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(evolution-pkcs11, 0.1, yuuma.sato@gmail.com)
AM_INIT_AUTOMAKE([foreign -Wall])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])

PKG_PROG_PKG_CONFIG

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_AR
AM_PROG_CC_C_O

LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES(EBOOK, libebook-1.2)
#PKG_CHECK_MODULES(EVO_SHELL, evolution-shell-3.0)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])
#AC_CHECK_HEADERS([nss3/cert.h nspr4/prtypes.h])
AC_CHECK_HEADER([glib.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 test/Makefile])
AC_OUTPUT
