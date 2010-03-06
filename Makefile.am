ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README CHANGELOG COPYRIGHT CREDITS sample.sql

AM_CFLAGS = -Wall

pammoddir = $(libdir)/security

pammod_LTLIBRARIES = pam_pgsql.la
#pam_pgsql_la_LIBRARIES =  @PGSQL_LIB@ @DEBUG_LIB@
#pam_pgsql_ladir = @moduledir@
pam_pgsql_la_LIBADD = -lpam -lpq
pam_pgsql_la_LDFLAGS = -module -export-dynamic -shared $(LDFLAGS_NOUNDEFINED)
pam_pgsql_la_SOURCES = \
			src/pam_pgsql.c \
			src/pam_pgsql.h \
			src/pam_pgsql_options.c \
			src/pam_pgsql_options.h \
			src/backend_pgsql.c \
			src/backend_pgsql.h \
			src/pam_get_service.c \
			src/pam_get_pass.c \
			src/md5.c \
			src/md5.h \
			src/sha1.c \
			src/sha1.h

if HAVE_PAM_CONV
EXTRA_PROGRAMS = authenticate chpass
endif

authenticate_LDADD = -lpam $(PAMCONVLIB)
authenticate_SOURCES = tests/authenticate.c

chpass_LDADD = -lpam $(PAMCONVLIB)
chpass_SOURCES = tests/chpass.c
