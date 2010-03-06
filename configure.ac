dnl Configure template for pam_pgsql

AC_PREREQ([2.62])
AC_INIT([pam-pgsql], 0.7,[http://sourceforge.net/tracker/?func=add&group_id=62198&atid=499727], pam-pgsql)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS([config.h])

AM_MAINTAINER_MODE

AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

#check programs
AC_DISABLE_STATIC
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AM_PROG_LIBTOOL

dnl Checks for libraries.
AC_CHECK_LIB(pam, pam_get_user)

dnl Checks for header files.
#AC_PATH_X
AC_FUNC_ALLOCA
AC_HEADER_RESOLV
AC_CHECK_HEADERS([syslog.h netdb.h malloc.h memory.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
#AC_TYPE_MODE_T
#AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
#AC_TYPE_UINT16_T
#AC_TYPE_UINT32_T
#AC_TYPE_UINT8_T
#AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit bzero gethostbyname memset mkdir pow socket sqrt strcasecmp strchr strdup strerror strndup strrchr strstr strtol strtoul])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])

AC_MSG_CHECKING(for PostgreSQL headers)
for d in /usr /usr/local /usr/local/pgsql; do
    test -f $d/include/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include)
    }
    test -f $d/include/postgresql/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include/postgresql"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include/postgresql)
    }
    test -f $d/include/postgresql/8.0/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include/postgresql/8.0"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include/postgresql/8.0)
    }
    test -f $d/include/pgsql/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include/pgsql"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include/pgsql)
    }
done

old_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -L$PG_DIR/lib"
AC_CHECK_LIB(pq, PQexecParams, 
    [AC_SUBST(PGSQL_LIB) 
        PGSQL_LIB="-L$PG_DIR/lib"],
    [AC_MSG_ERROR(could not determine PostgreSQL library location)])
LDFLAGS="$old_LDFLAGS"

AC_SUBST(PGSQL_LIB) 

if test "`uname`" = "Linux" >/dev/null 2>/dev/null; then
    # Debian needs this
    PAM_MISC_LD="-lpam_misc"
	 INSTALLPAM="/lib/security/"
	 AC_DEFINE([LINUX], [1], [It is a linux machine])
else
    PAM_MISC_LD=""
	 INSTALLPAM="/usr/lib/"
fi

AC_SUBST(PAM_MISC_LD)
AC_SUBST(INSTALLPAM)
AC_SUBST(DEBUG)
AC_SUBST(DEBUG_LIB)
AC_SUBST([moduledir])

AC_ARG_WITH(debug, 
[  --with-debug            Enable debugging routines], 
[AC_DEFINE([DEBUG], [], [Debug]) 
    AC_CHECK_LIB(efence, malloc, [DEBUG_LIB="-lefence"])
    DEBUG="-g"],
[DEBUG=""; DEBUG_LIB=""])

AC_OUTPUT
