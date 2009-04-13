#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __PAM_PG_OPTIONS_H_
#define __PAM_PG_OPTIONS_H_

#define PAM_PGSQL_FILECONF                 "/etc/pam_pgsql.conf"
#define PAM_PGSQL_PORT                     5432

typedef struct modopt_s {

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
void free_mod_options(modopt_t *options);

#endif
