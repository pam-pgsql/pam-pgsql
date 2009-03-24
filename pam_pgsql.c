/*
 * PAM authentication module for PostgreSQL
 * 
 * Based in part on pam_unix.c of FreeBSD. See debian/copyright
 * for licensing details.
 *
 * David D.W. Downey ("pgpkeys") <david-downey@codecastle.com> et al. (see debian/copyright)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <mhash.h>
#include <time.h>
#include <sys/time.h>
#include <libpq-fe.h>
#include <crypt.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#include "pam_mod_misc.h"

#define PASSWORD_PROMPT         "Password: "
#define PASSWORD_PROMPT_NEW	    "New password: "
#define PASSWORD_PROMPT_CONFIRM "Confirm new password: "
#define CONF                    "/etc/pam_pgsql.conf"

#define DBGLOG(x...)  if(options->debug) {                          \
                          openlog("PAM_pgsql", LOG_PID, LOG_AUTH);  \
                          syslog(LOG_DEBUG, ##x);                   \
                          closelog();                               \
                      }
#define SYSLOG(x...)  do {                                          \
                          openlog("PAM_pgsql", LOG_PID, LOG_AUTH);  \
                          syslog(LOG_INFO, ##x);                    \
                          closelog();                               \
                      } while(0);

/* private: parse and set the specified string option */
static void
set_module_option(const char *option, struct module_options *options)
{
	char *buf, *eq;
	char *val, *end;

	if(!option || !*option)
		return;

	buf = strdup(option);

	if((eq = strchr(buf, '='))) {
		end = eq - 1;
		val = eq + 1;
		while(end > buf && isspace(*end))
			end--;
		end++;
		*end = '\0';
		while(*val && isspace(*val))
			val++;
	} else 
		val = NULL;
    
	DBGLOG("setting option: %s=>%s\n", buf, val);

	if(!strcmp(buf, "connect")) {
		options->pg_conn_str = strdup(val);
	} else if(!strcmp(buf, "auth_query")) {
		options->auth_query = strdup(val); 
	} else if(!strcmp(buf, "auth_succ_query")) {
		options->auth_succ_query = strdup(val); 
	} else if(!strcmp(buf, "auth_fail_query")) {
		options->auth_fail_query = strdup(val); 
	} else if(!strcmp(buf, "acct_query")) {
		options->acct_query = strdup(val);
	} else if(!strcmp(buf, "pwd_query")) {
		options->pwd_query = strdup(val);        
	} else if(!strcmp(buf, "session_open_query")) {
		options->session_open_query = strdup(val);        
	} else if(!strcmp(buf, "session_close_query")) {
		options->session_close_query = strdup(val);        
	} else if(!strcmp(buf, "database")) {
		options->database = strdup(val); /* deprecated by connect*/
	} else if(!strcmp(buf, "table")) {
		options->table = strdup(val); /* deprecated auth_query, acct_query, pwd_query*/
	} else if(!strcmp(buf, "host")) { 
		options->db_host = strdup(val); /*deprecated by connect*/
	} else if(!strcmp(buf, "port")) {
		options->db_port = strdup(val); /*deprecated by connect*/
	} else if(!strcmp(buf, "timeout")) {
		options->db_timeout = strdup(val); /*deprecated by connect*/
	} else if(!strcmp(buf, "user")) {
		options->db_user = strdup(val); /*deprecated by connect*/
	} else if(!strcmp(buf, "password")) {
		options->db_password = strdup(val); /*deprecated by connect*/
	} else if(!strcmp(buf, "user_column")) {
		options->user_column = strdup(val); /* deprecated auth_query, acct_query, pwd_query*/
	} else if(!strcmp(buf, "pwd_column")) {
		options->pwd_column = strdup(val); /* deprecated auth_query, acct_query, pwd_query*/
	} else if(!strcmp(buf, "expired_column")) {
		options->expired_column = strdup(val); /* deprecated auth_query, acct_query, pwd_query*/
	} else if(!strcmp(buf, "newtok_column")) {
		options->newtok_column = strdup(val);
	} else if(!strcmp(buf, "config_file")) { 
		options->config_file = strdup(val);
	} else if(!strcmp(buf, "pw_type")) { 
		options->pw_type = PW_CLEAR;
		if(!strcmp(val, "md5")) {
			options->pw_type = PW_MD5;
		} else if(!strcmp(val, "crypt")) {
			options->pw_type = PW_CRYPT;
		} else if(!strcmp(val, "crypt_md5")) {
			options->pw_type = PW_CRYPT_MD5;
		}
	} else if(!strcmp(buf, "debug")) {
		options->debug = 1;
	}
	free(buf);
}

/* very private: used only in get_module_options */
static char *
build_connect_string(struct module_options *options)
{
    int len;
    char *str;

    len = strlen(options->database) + strlen(" dbname=") 
	+ (options->db_host ? (strlen(options->db_host) + strlen(" host=")) : 0)
	+ (options->db_port ? (strlen(options->db_port) + strlen(" port=")) : 0)
	+ (options->db_timeout ? (strlen(options->db_timeout) + strlen(" connect_timeout=")) : 0) 
	+ (options->db_user ? (strlen(options->db_user) + strlen(" user=")) : 0)
	+ (options->db_password ? (strlen(options->db_password) + strlen(" password=")) : 0)
	+ 1;

    str = (char *) malloc(len);
    memset(str, 0, len);

    if(str == NULL)
	return NULL;
	
    /* SAFE */
    strncat(str, "dbname=", strlen("dbname="));
    strncat(str, options->database, strlen(options->database));
    if(options->db_host) {
	strncat(str, " host=", strlen(" host="));
	strncat(str, options->db_host, strlen(options->db_host));
    }
    if(options->db_port) {
	strncat(str, " port=", strlen(" port="));
	strncat(str, options->db_port, strlen(options->db_port));
    }    
    if(options->db_timeout) {
	strncat(str, " connect_timeout=", strlen(" connect_timeout="));
	strncat(str, options->db_timeout, strlen(options->db_timeout));
    }
    if(options->db_user) {
	strncat(str, " user=", strlen(" user="));
	strncat(str, options->db_user, strlen(options->db_user));
    }
    if(options->db_password) {
	strncat(str, " password=", strlen(" password="));
	strncat(str, options->db_password, strlen(options->db_password));
    }
    return str;
}

static int
options_valid(struct module_options *options)
{
	if (options->pg_conn_str == 0 || options->auth_query == 0) {
		SYSLOG("the database connection string and auth_query options are required.");
		return PAM_AUTH_ERR;
	}
	return PAM_SUCCESS;
}

/* private: read module options from file or commandline */
static int 
get_module_options(int argc, const char **argv, struct module_options **options)
{


	int i;
	FILE *fp;
	struct module_options *opts;

	opts = (struct module_options *)malloc(sizeof *opts);
	if (!opts) 
		return PAM_BUF_ERR;
	bzero(opts, sizeof(*opts));
	opts->pw_type = PW_CLEAR;

	opts->config_file=CONF;
	for(i = 0; i < argc; i++)  
		if (!strncmp(argv[i],"config_file",11)) set_module_option(argv[i], opts);
	
	if((fp = fopen(opts->config_file, "r"))) {
		char line[4096];
		char *str, *end;

		while (fgets(line, sizeof(line), fp)) {
			str = line;
			end = line + strlen(line) - 1;
			while(*str && isspace(*str))
				str++;
			while (end > str && isspace(*end))
				end--;
			end++;
			*end = '\0';
			set_module_option(str, opts);
		}

		fclose(fp);
	}

	for(i = 0; i < argc; i++) {
		if (pam_std_option(opts, argv[i]) != 0)
			set_module_option(argv[i], opts);
	}

/**************************** compatibility code for old version of configuration file *************************/

	if (opts->pg_conn_str == 0) 
		if (opts->database != 0)
			opts->pg_conn_str = build_connect_string(opts);
			
	if (opts->auth_query == 0) 
		if (opts->pwd_column != 0 && opts->table != 0 && opts->user_column !=0) {
			opts->auth_query = malloc(32+strlen(opts->pwd_column)+strlen(opts->table)+strlen(opts->user_column));
			sprintf(opts->auth_query, "select %s from %s where %s = %%u", opts->pwd_column, opts->table, opts->user_column);
		}
		
	if (opts->acct_query == 0)  {
		if (opts->expired_column != 0 && opts->newtok_column != 0 && opts->table != 0 && opts->user_column !=0 && opts->pwd_column != 0) {
			opts->acct_query = malloc(96+2*strlen(opts->expired_column)+2*strlen(opts->newtok_column)+2*strlen(opts->pwd_column)+strlen(opts->table)+ strlen(opts->user_column));
			sprintf(opts->acct_query, "select (%s = 'y' OR %s = '1'), (%s = 'y' OR %s = '1'), (%s IS NULL OR %s = '') from %s where %s = %%u", opts->expired_column, 
				opts->expired_column, opts->newtok_column, opts->newtok_column, opts->pwd_column, opts->pwd_column, opts->table, opts->user_column);
		} else if (opts->newtok_column != 0 && opts->table != 0 && opts->user_column !=0 && opts->pwd_column != 0) {
			opts->acct_query = malloc(96+2*strlen(opts->newtok_column)+2*strlen(opts->pwd_column)+strlen(opts->table)+ strlen(opts->user_column));
			sprintf(opts->acct_query, "select false, (%s = 'y' OR %s = '1'), (%s IS NULL OR %s = '') from %s where %s = %%u", 
				opts->newtok_column, opts->newtok_column, opts->pwd_column, opts->pwd_column, opts->table, opts->user_column);
		} else if (opts->expired_column != 0 && opts->table != 0 && opts->user_column !=0 && opts->pwd_column != 0) {
			opts->acct_query = malloc(96+2*strlen(opts->expired_column)+2*strlen(opts->pwd_column) + strlen(opts->table)+ strlen(opts->user_column));
			sprintf(opts->acct_query, "select (%s = 'y' OR %s = '1'), false, (%s IS NULL OR %s = '') from %s where %s = %%u", 
				opts->expired_column, opts->expired_column, opts->pwd_column, opts->pwd_column, opts->table, opts->user_column);
		}
	}

	
	if (opts->pwd_query == 0)
		if (opts->pwd_column != 0 && opts->table != 0 && opts->user_column != 0) {
			opts->pwd_query = malloc(40+strlen(opts->pwd_column)+strlen(opts->table)+strlen(opts->user_column));
			sprintf(opts->pwd_query, "update %s set %s = %%p where %s = %%u", opts->table, opts->pwd_column, opts->user_column);		
		}
		
	*options = opts;

	return options_valid(opts);
}

/* private: free module options returned by get_module_options() */
static void
free_module_options(struct module_options *options)
{
    if(options == NULL) /* Don't try to free NULL struct */
        return;
	if(options->pg_conn_str)
		free(options->pg_conn_str);
	if(options->auth_query)
		free(options->auth_query);
	if(options->acct_query)
		free(options->acct_query);
	if(options->pwd_query)
		free(options->pwd_query);
    if(options->session_open_query)
        free(options->session_open_query);
    if(options->session_close_query)
        free(options->session_close_query);
	if(options->database)
		free(options->database);
	if(options->table)
		free(options->table);
	if(options->db_host)
		free(options->db_host);
	if(options->db_port)
		free(options->db_port);
	if(options->db_timeout)
		free(options->db_timeout);        
	if(options->db_user)
		free(options->db_user);
	if(options->db_password)
		free(options->db_password);
	if(options->user_column)
		free(options->user_column);
	if(options->pwd_column)
		free(options->pwd_column);
	if(options->expired_column)
		free(options->expired_column);
	if(options->newtok_column)
		free(options->newtok_column);
	bzero(options, sizeof(*options));
	free(options);
}

/* private: open connection to PostgreSQL */
static PGconn *
pg_connect(struct module_options *options)
{
	PGconn *conn;
	conn = PQconnectdb(options->pg_conn_str);
	if(PQstatus(conn) != CONNECTION_OK) {
		SYSLOG("PostgreSQL connection failed: '%s'", PQerrorMessage(conn));
		return NULL;
	}
	return conn;
}

/* private: expand query; partially stolen from mailutils */

static int
expand_query (char **command, const char** values, const char *query, const char *service, const char *user, const char *passwd, const char *rhost, const char *raddr)
{
	char *p, *q, *res;
	unsigned int len;
	unsigned int nparm=0;
  
	if (!query) {
		*command = NULL;
		return 0;
	}
	/* Compute resulting query length */
	for (len = 0, p = (char *) query; *p; ) {
		if (*p == '%') {
			if (p[1] == 'u' || p[1] == 'p' || p[1] == 's') {
				len += 4; /*we allow 128 tokens max*/
				p += 2;
				continue;
			} else if (p[1] == '%') {
				len++;
				p += 2;
				continue;
			}
		}
		len++;
		p++;  
	}
	res = malloc (len + 1);
	if (!res) {
		*command = NULL;
		return 0;
	}
	for (p = (char *) query, q = res; *p; ) {
		if (*p == '%') {
			switch (*++p) {
				case 'u': {
					sprintf(q, "$%i", ++nparm);
					values[nparm-1] = user;
					q += strlen (q);
					p++;
				}
				break;
				case 'p': {
					sprintf(q, "$%i", ++nparm);
					values[nparm-1] = passwd;
					q += strlen (q);
					p++;
				}
				break;
				case 's': {
					sprintf(q, "$%i", ++nparm);
					values[nparm-1] = service;
					q += strlen (q);
					p++;
				}
				break;
				case 'h': {
					sprintf(q, "$%i", ++nparm);
					values[nparm-1] = rhost;
					q += strlen (q);
					p++;
				}
				break;
				case 'i': {
					sprintf(q, "$%i", ++nparm);
					values[nparm-1] = raddr;
					q += strlen (q);
					p++;
					if (!raddr) {
						if (strchr(rhost, '.') != NULL) {
							*command = NULL;
							free (res);
							return 0;
						}
					}
				}
				break;
				case '%':
				default:
					*q++ = *p++;
				break;
			}
		} else	*q++ = *p++;
	 }
	 *q = 0;
	 
	 *command = res;
	 values[nparm] = NULL; 
	 return nparm;
}

/* private: execute query */
static int
pg_execParam(PGconn *conn, PGresult **res, 
        const char *query, const char *service, const char *user, const char *passwd, const char *rhost)
{
	int nparm = 0;
	const char *values[128];
	char *command, *raddr;
	struct hostent *hentry;
	
	if (!conn) 
		return PAM_AUTHINFO_UNAVAIL;
	bzero(values, sizeof(*values));
	
	raddr = NULL;
	
	if(rhost != NULL && (hentry = gethostbyname(rhost)) != NULL) {
		/* Make IP string */
		raddr = malloc(16);
		sprintf(raddr, "%d.%d.%d.%d",
			hentry->h_addr_list[0][0],
			hentry->h_addr_list[0][1],
			hentry->h_addr_list[0][2],
			hentry->h_addr_list[0][3]);
		raddr[15] = 0;
	}
	
	nparm = expand_query(&command, values, query, service, user, passwd, rhost, raddr);
	if (command == NULL) 
		return PAM_AUTH_ERR;
	
	*res = PQexecParams(conn, command, nparm, 0, values, 0, 0, 0);
	free (command);
	free (raddr);
    
	if(PQresultStatus(*res) != PGRES_COMMAND_OK && PQresultStatus(*res) != PGRES_TUPLES_OK) {
		SYSLOG("PostgreSQL query failed: '%s'", PQresultErrorMessage(*res));
		return PAM_AUTHINFO_UNAVAIL;
	}
	return PAM_SUCCESS;
}

/* private: convert an integer to a radix 64 character */
static int
i64c(int i)
{
	if (i <= 0)
		return ('.');
	if (i == 1)
		return ('/');
	if (i >= 2 && i < 12)
		return ('0' - 2 + i);
	if (i >= 12 && i < 38)
		return ('A' - 12 + i);
	if (i >= 38 && i < 63)
		return ('a' - 38 + i);
	return ('z');
}

/* private: generate random salt character */
static char *
crypt_make_salt(struct module_options *options)
{
	static char result[12];
	int len,pos;
	struct timeval now;

	if(options->pw_type==PW_CRYPT){
		len=2;
		pos=0;
	} else { /* PW_CRYPT_MD5 */
		strcpy(result,"$1$");
		len=11;
		pos=3;
	}
	gettimeofday(&now,NULL);
	srandom(now.tv_sec*10000+now.tv_usec/100+clock());
	while(pos<len)result[pos++]=i64c(random()&63);
	result[len]=0;
	return result;
}

/* private: encrypt password using the preferred encryption scheme */
static char *
encrypt_password(struct module_options *options, const char *pass, const char *salt)
{
	char *s = NULL;

	switch(options->pw_type) {
		case PW_CRYPT:
		case PW_CRYPT_MD5:
			if (salt==NULL) {
				s = strdup(crypt(pass, crypt_make_salt(options)));
			} else {
				s = strdup(crypt(pass, salt));
			}
		break;
		case PW_MD5: {
			char *buf;
			int buf_size;
			MHASH handle;
			unsigned char *hash;
			handle = mhash_init(MHASH_MD5);
			if(handle == MHASH_FAILED) {
				SYSLOG("could not initialize mhash library!");
			} else {
				unsigned int i;
				mhash(handle, pass, strlen(pass));
				hash = mhash_end(handle);
				if (hash != NULL) {
					buf_size = (mhash_get_block_size(MHASH_MD5) * 2)+1;
					buf = (char *)malloc(buf_size);
					bzero(buf, buf_size);

					for(i = 0; i < mhash_get_block_size(MHASH_MD5); i++) {
						sprintf(&buf[i * 2], "%.2x", hash[i]);
					}
					free(hash);
					s = buf;
				} else {
					s = strdup("!");
				}
			}
		}
		break;
		case PW_CLEAR:
		default:
			s = strdup(pass);
	}
	return s;
}

/* private: authenticate user and passwd against database */
static int
auth_verify_password(const char *service, const char *user, const char *passwd, const char *rhost,
                     struct module_options *options)
{
	PGresult *res;
	PGconn *conn;
	int rc;
	char *tmp;

	if(!(conn = pg_connect(options)))
		return PAM_AUTH_ERR;

	DBGLOG("query: %s", options->auth_query);
	rc = PAM_AUTH_ERR;	
	if(pg_execParam(conn, &res, options->auth_query, service, user, passwd, rhost) == PAM_SUCCESS) {
		if(PQntuples(res) == 0) {
			rc = PAM_USER_UNKNOWN;
		} else {
			char *stored_pw = PQgetvalue(res, 0, 0);
			if (!strcmp(stored_pw, (tmp = encrypt_password(options, passwd, stored_pw)))) rc = PAM_SUCCESS; 
			free (tmp);
		}
		PQclear(res);
	}
	PQfinish(conn);
	return rc;
}

/* public: authenticate user */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct module_options *options = NULL;
	const char *user, *password, *rhost;
	int rc;
	PGresult *res;
	PGconn *conn;	
	
	user = NULL; password = NULL; rhost = NULL;

	if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {
		if ((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
			if ((rc = get_module_options(argc, argv, &options)) == PAM_SUCCESS) {
				DBGLOG("attempting to authenticate: %s", user);
				if ((rc = pam_get_pass(pamh, PAM_AUTHTOK, &password, PASSWORD_PROMPT, options->std_flags)) == PAM_SUCCESS) {
					if ((rc = auth_verify_password(pam_get_service(pamh), user, password, rhost, options)) == PAM_SUCCESS) {
						if ((password == 0 || *password == 0) && (flags & PAM_DISALLOW_NULL_AUTHTOK)) {
							rc = PAM_AUTH_ERR; 
						} else {
							SYSLOG("(%s) user %s authenticated.", pam_get_service(pamh), user);
						}
					}
				}
			}
		}
	}
	
	if (rc == PAM_SUCCESS) {
		if (options->auth_succ_query) {
			if ((conn = pg_connect(options))) {
				pg_execParam(conn, &res, options->auth_succ_query, pam_get_service(pamh), user, password, rhost);
				PQclear(res);
				PQfinish(conn);
			}
		}
	} else {
		if (options->auth_fail_query) {
			if ((conn = pg_connect(options))) {
				pg_execParam(conn, &res, options->auth_fail_query, pam_get_service(pamh), user, password, rhost);
				PQclear(res);
				PQfinish(conn);
			}
		}
	}

	free_module_options(options);
	return rc;
}

/* public: check if account has expired, or needs new password */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                            const char **argv)
{
	struct module_options *options = NULL;
	const char *user, *rhost;
	int rc;
	PGconn *conn;
	PGresult *res;
	
	user = NULL; rhost = NULL;
    
	if ((rc = get_module_options(argc, argv, &options)) == PAM_SUCCESS) {
		/* query not specified, just succeed. */
		if (options->acct_query == 0) {
			free_module_options(options);
			return PAM_SUCCESS;
		}
		
		if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {
			if((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
				if(!(conn = pg_connect(options))) {
					rc = PAM_AUTH_ERR;
				} else {
					DBGLOG("query: %s", options->acct_query);
					rc = PAM_AUTH_ERR;
					if(pg_execParam(conn, &res, options->acct_query, pam_get_service(pamh), user, NULL, rhost) == PAM_SUCCESS) {
						if (PQntuples(res) > 0 && PQnfields(res)>=2) {
							char *expired_db = PQgetvalue(res, 0, 0);
							char *newtok_db = PQgetvalue(res, 0, 1);
							rc = PAM_SUCCESS;
							if (PQnfields(res)>=3) {
								char *nulltok_db = PQgetvalue(res, 0, 2);
								if ((!strcmp(nulltok_db, "t")) && (flags & PAM_DISALLOW_NULL_AUTHTOK))
									rc = PAM_NEW_AUTHTOK_REQD;
							}
							if (PQnfields(res)>=4) {
								char *nulltok_db = PQgetvalue(res, 0, 3);
								rc = PAM_PERM_DENIED;
							}							
							if (!strcmp(newtok_db, "t"))
								rc = PAM_NEW_AUTHTOK_REQD;
							if (!strcmp(expired_db, "t"))
								rc = PAM_ACCT_EXPIRED;
						}
						PQclear(res);
					}
					PQfinish(conn);
				}
			}
		}
	}
	
	free_module_options(options);
	return rc;
}

/* public: change password */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct module_options *options = NULL;
	int rc;
	const char *user, *pass, *newpass, *rhost;
	const void *oldtok;
	char *newpass_crypt;
	PGconn *conn;
	PGresult *res;
	
	user = NULL; pass = NULL; newpass = NULL; rhost = NULL; newpass_crypt = NULL;

	if ((rc =get_module_options(argc, argv, &options)) == PAM_SUCCESS) 
		if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) 
			rc = pam_get_user(pamh, &user, NULL);
		

	if ((rc == PAM_SUCCESS) && (flags & PAM_PRELIM_CHECK)) {
		if (getuid() != 0) {
			if ((rc = pam_get_pass(pamh, PAM_OLDAUTHTOK, &pass, PASSWORD_PROMPT, options->std_flags)) == PAM_SUCCESS) {
				rc = auth_verify_password(pam_get_service(pamh), user, pass, rhost, options);
			} else {
				SYSLOG("could not retrieve password from '%s'", user);
			}
		} else {
			rc = PAM_SUCCESS;
		}
	} else if ((rc == PAM_SUCCESS) && (flags & PAM_UPDATE_AUTHTOK)) {
		/* only try to check old password if user is not root */
		pass = newpass = NULL;
		if (getuid() != 0) {
			if ((rc = pam_get_item(pamh, PAM_OLDAUTHTOK, &oldtok)) == PAM_SUCCESS) {
				pass = (const char*) oldtok;
				if ((rc = auth_verify_password(pam_get_service(pamh), user, pass, rhost, options)) != PAM_SUCCESS) {
					SYSLOG("(%s) user '%s' not authenticated.", pam_get_service(pamh), user);
				}			
			} else {
				SYSLOG("could not retrieve old token");
			}

                 } else {
                 	rc = PAM_SUCCESS;	
                 }			
				
		if (rc == PAM_SUCCESS) {
			if ((rc = pam_get_confirm_pass(pamh, &newpass, PASSWORD_PROMPT_NEW, PASSWORD_PROMPT_CONFIRM, options->std_flags)) == PAM_SUCCESS) {
				if((newpass_crypt = encrypt_password(options, newpass, NULL))) {
					if(!(conn = pg_connect(options))) {
						rc = PAM_AUTHINFO_UNAVAIL;
					}
					if (rc == PAM_SUCCESS) {
						DBGLOG("query: %s", options->pwd_query);
						if(pg_execParam(conn, &res, options->pwd_query, pam_get_service(pamh), user, newpass_crypt, rhost) != PAM_SUCCESS) {
							rc = PAM_AUTH_ERR;
						} else {
							SYSLOG("(%s) password for '%s' was changed.", pam_get_service(pamh), user);
							PQclear(res);
						}
						PQfinish(conn);
					}
					free (newpass_crypt);
				} else {
					rc = PAM_BUF_ERR;
				}						
			} else {
				SYSLOG("could not retrieve new authentication tokens");
			}
		}
	}
	free_module_options(options);
	if (flags & (PAM_PRELIM_CHECK | PAM_UPDATE_AUTHTOK))
		return rc;
	else
		return PAM_AUTH_ERR;
}

/* public: just succeed. */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
            int argc, const char **argv)
{
	struct module_options *options = NULL;
	const char *user, *rhost;
	int rc;
	PGresult *res;
	PGconn *conn;	
	
	user = NULL; rhost = NULL;

	if ((rc = get_module_options(argc, argv, &options)) == PAM_SUCCESS) {
	  if (options->session_open_query) {
	    if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {
		if ((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
			DBGLOG("Session opened for user: %s", user);
			if ((conn = pg_connect(options))) {
                          pg_execParam(conn, &res, options->session_open_query, pam_get_service(pamh), user, NULL, rhost);
                          PQclear(res);
                          PQfinish(conn);
			}
		}
        }
    }
	free_module_options(options);
    }

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
            int argc, const char *argv[])
{
	struct module_options *options = NULL;
	const char *user, *rhost;
	int rc;
	PGresult *res;
	PGconn *conn;	
	
	user = NULL; rhost = NULL;

	if ((rc = get_module_options(argc, argv, &options)) == PAM_SUCCESS) {
	if (options->session_close_query) {
	    if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {
		if ((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
			DBGLOG("Session opened for user: %s", user);
			if ((conn = pg_connect(options))) {
                          pg_execParam(conn, &res, options->session_close_query, pam_get_service(pamh), user, NULL, rhost);
                          PQclear(res);
                          PQfinish(conn);
			}
		}
        }
    }
	free_module_options(options);
    }

    return (PAM_SUCCESS);
}

