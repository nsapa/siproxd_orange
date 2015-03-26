AC_INIT([siproxd_orange], [0.2], [http://code.x0r.fr/siproxd_orange/issues], [siproxd_orange], [http://code.x0r.fr/siproxd_orange])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([foreign -Wall -Werror dist-bzip2 subdir-objects])
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR
AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AC_PREFIX_PROGRAM([siproxd])

AC_CONFIG_MACRO_DIR([m4])


dnl define macro to check for some siproxd source files
AC_DEFUN([CHECK_SIPROXD_FILE], [AC_CHECK_FILE([siproxd/src/$1], [], [
	echo 'No $1 header could be found.';
	echo 'Please make sure there is a symlink named "siproxd" in the root directory,';
	echo 'which points to a siproxd source code directory. Please read README.md ';
	echo 'for more information.';
	echo;
	echo 'Example: ln -s /path/to/siproxd-0.8.2-dev siproxd';
	exit 1])])

dnl Check for libraries
PKG_CHECK_MODULES([libcurl], [libcurl])
LIBS="$libcurl_LIBS $LIBS"
CFLAGS="$libcurl_CFLAGS $CFLAGS"

PKG_CHECK_MODULES([libxml], [libxml-2.0], [],
	[
	libxml_CFLAGS="-I/usr/include/libxml2 -I/usr/local/include/libxml2"
	libxml_LIBS="-lxml2"
	AC_CHECK_LIB([xml2], [xmlReadMemory], [], [
		echo 'You need libxml2 in order to build this program'; 
		exit 1])
	]
)
LIBS="$libxml_LIBS $LIBS"
CFLAGS="$libxml_CFLAGS $CFLAGS"
CPPFLAGS="$libxml_CFLAGS $CFLAGS"

AC_CHECK_HEADERS([ltdl.h], [], [
	echo 'You need libltdl in order to build this program';
	exit 1])



dnl Check endianness
AC_C_BIGENDIAN(
	[AC_DEFINE([WORDS_BIGENDIAN], [1], [Define to 1 if target is big endian])],
	[AC_DEFINE([WORDS_LITTLEENDIAN], [1], [Define to 1 if target is little endian])]
)

dnl Check types
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

dnl Check functions
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strncmp])
AC_FUNC_MALLOC
AC_FUNC_REALLOC

dnl Check for headers
AC_CHECK_HEADERS([curl/curl.h])
AC_CHECK_HEADERS([libxml/parser.h])
AC_CHECK_HEADERS([libxml/tree.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h])
AC_CHECK_HEADERS([sys/endian.h endian.h])

dnl Check for htole32
AC_MSG_CHECKING([the presence of htole32])
AC_TRY_LINK([
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif], 
	[uint32_t y = htole32(0x42)], 
	[have_htole32=yes],
	[have_htole32=no])
if test "$have_htole32" = yes; then
	AC_DEFINE([HAVE_HTOLE32], [1], [Define if htole32 function or macro exists])
fi
AC_MSG_RESULT($have_htole32)

dnl Check for htole16
AC_MSG_CHECKING([the presence of htole16])
AC_TRY_LINK([
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif], 
	[uint16_t y = htole16(0x42)], 
	[have_htole16=yes],
	[have_htole16=no])
if test "$have_htole16" = yes; then
	AC_DEFINE([HAVE_HTOLE16], [1], [Define if htole16 function or macro exists])
fi
AC_MSG_RESULT($have_htole16)

CHECK_SIPROXD_FILE([siproxd.h])
CHECK_SIPROXD_FILE([plugins.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
