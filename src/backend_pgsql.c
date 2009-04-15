/*
 * PAM authentication module for PostgreSQL
 * 
 * Based in part on pam_unix.c of FreeBSD. See COPYRIGHT
 * for licensing details.
 *
 * David D.W. Downey ("pgpkeys") <david-downey@codecastle.com> et al. (see COPYRIGHT)
 * William Grzybowski <william@agencialivre.com.br>
 */

#define _XOPEN_SOURCE 500
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
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

#include "backend_pgsql.h"
#include "pam_pgsql.h"

/* very private: used only in get_module_options */
char *
build_conninfo(modopt_t *options)
{
    char *str;

	 if(options == NULL)
		 return NULL;

	 str = (char *) malloc(sizeof(char)*512);
    memset(str, 0, 512);

    /* SAFE */
    strncat(str, "dbname=", strlen("dbname="));
    strncat(str, options->db, strlen(options->db));

	if(options->host) {
		strncat(str, " host=", strlen(" host="));
		strncat(str, options->host, strlen(options->host));
	}
	if(options->port) {
		strncat(str, " port=", strlen(" port="));
		strncat(str, options->port, strlen(options->port));
	}    
	if(options->timeout) {
		strncat(str, " connect_timeout=", strlen(" connect_timeout="));
		strncat(str, options->timeout, strlen(options->timeout));
	}
	if(options->user) {
		strncat(str, " user=", strlen(" user="));
		strncat(str, options->user, strlen(options->user));
	}
	if(options->passwd) {
		strncat(str, " password=", strlen(" password="));
		strncat(str, options->passwd, strlen(options->passwd));
	}
	if(options->sslmode) {
		strncat(str, " sslmode=", strlen(" sslmode="));
		strncat(str, options->sslmode, strlen(options->sslmode));
	}

	return str;
}

/* private: open connection to PostgreSQL */
PGconn *
db_connect(modopt_t *options)
{
	PGconn *conn;
	if(options->connstr == NULL)
		options->connstr = build_conninfo(options);

	conn = PQconnectdb(options->connstr);
	if(PQstatus(conn) != CONNECTION_OK) {
		SYSLOG("PostgreSQL connection failed: '%s'", PQerrorMessage(conn));
		return NULL;
	}
	return conn;
}

/* private: expand query; partially stolen from mailutils */

int
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
int
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

/* authenticate user and passwd against database */
int
backend_authenticate(const char *service, const char *user, const char *passwd, const char *rhost, modopt_t *options)
{
	PGresult *res;
	PGconn *conn;
	int rc;
	char *tmp;

	if(!(conn = db_connect(options)))
		return PAM_AUTH_ERR;

	DBGLOG("query: %s", options->query_auth);
	rc = PAM_AUTH_ERR;	
	if(pg_execParam(conn, &res, options->query_auth, service, user, passwd, rhost) == PAM_SUCCESS) {
		if(PQntuples(res) == 0) {
			rc = PAM_USER_UNKNOWN;
		} else {
			char *stored_pw = PQgetvalue(res, 0, 0);
			if (!strcmp(stored_pw, (tmp = password_encrypt(options, passwd, stored_pw)))) rc = PAM_SUCCESS; 
			free (tmp);
		}
		PQclear(res);
	}
	PQfinish(conn);
	return rc;
}

/* private: encrypt password using the preferred encryption scheme */
char *
password_encrypt(modopt_t *options, const char *pass, const char *salt)
{
	char *s = NULL;

	switch(options->pw_type) {
		case PW_CRYPT:
		case PW_CRYPT_MD5:
			if (salt==NULL) {
				s = strdup(crypt(pass, crypt_makesalt(options->pw_type)));
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
		case PW_SHA1: {
			char *buf;
			int buf_size;
			MHASH handle;
			unsigned char *hash;
			handle = mhash_init(MHASH_SHA1);
			if(handle == MHASH_FAILED) {
				SYSLOG("could not initialize mhash library!");
			} else {
				unsigned int i;
				mhash(handle, pass, strlen(pass));
				hash = mhash_end(handle);
				if (hash != NULL) {
					buf_size = (mhash_get_block_size(MHASH_SHA1) * 2)+1;
					buf = (char *)malloc(buf_size);
					bzero(buf, buf_size);

					for(i = 0; i < mhash_get_block_size(MHASH_SHA1); i++) {
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

char *
crypt_makesalt(pw_scheme scheme)
{
	static char result[12];
	int len,pos;
	struct timeval now;

	if(scheme==PW_CRYPT){
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
