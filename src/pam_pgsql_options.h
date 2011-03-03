#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __PAM_PG_OPTIONS_H_
#define __PAM_PG_OPTIONS_H_

#define PAM_PGSQL_FILECONF                 SYSCONFDIR "/pam_pgsql.conf"
#define PAM_PGSQL_PORT                     5432

#include <sys/cdefs.h>

#define PAM_OPT_DEBUG			0x01
#define PAM_OPT_NO_WARN			0x02
#define PAM_OPT_USE_FIRST_PASS		0x04
#define	PAM_OPT_TRY_FIRST_PASS		0x08
#define PAM_OPT_USE_MAPPED_PASS		0x10
#define PAM_OPT_ECHO_PASS		0x20
#define PAM_OPT_TRY_OLDAUTH		0x40
#define PAM_OPT_USE_OLDAUTH		0x80

typedef enum {
    PW_CLEAR = 1, 
    PW_MD5,
    PW_CRYPT,
    PW_CRYPT_MD5,
    PW_SHA1,
    PW_MD5_POSTGRES
} pw_scheme;

typedef struct modopt_s {

   char *connstr;
   char *fileconf;
   char *host;
   char *db;
	char *table;
	char *timeout;
   char *user;
   char *passwd;
   char *sslmode;
	char *column_pwd;
	char *column_user;
	char *column_expired;
	char *column_newpwd;
	char *query_acct;
	char *query_pwd;
	char *query_auth;
	char *query_auth_succ;
	char *query_auth_fail;
	char *query_session_open;
	char *query_session_close;
   char *port;
	int pw_type;
   int debug;
	int std_flags;

} modopt_t;

modopt_t * mod_options(int , const char **);


int  pam_get_pass(pam_handle_t *, int, const char **, const char *, int);
int  pam_get_confirm_pass(pam_handle_t *, const char **, const char *,  const char *, int);
const char *pam_get_service(pam_handle_t *pamh);

#endif
