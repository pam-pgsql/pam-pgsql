#AM_CFLAGS = -Wall -pedantic
AM_CFLAGS = -Wall

noinst_PROGRAMS = authenticate chpass

authenticate_LDADD = @PAM_MISC_LD@ -lpam
authenticate_SOURCES = \
							  authenticate.c

chpass_LDADD = @PAM_MISC_LD@ -lpam 
chpass_SOURCES = \
							  chpass.c

