#AM_CFLAGS = -Wall -pedantic
AM_CFLAGS = -Wall

noinst_PROGRAMS = authenticate

authenticate_LDADD = @PAM_MISC_LD@ -lpam -lpam_misc
authenticate_SOURCES = \
							  authenticate.c \
							  chpass.c


