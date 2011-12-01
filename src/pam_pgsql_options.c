/*
 * PAM authentication module for PostgreSQL
 *
 * William Grzybowski <william@agencialivre.com.br>
 */


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "pam_pgsql.h"
#include "pam_pgsql_options.h"

static void
read_config_file(modopt_t *options) {

    FILE *fp;
    char buffer[1024];
    char *eq,*val,*end;

    fp = fopen(options->fileconf, "r");
    if (errno == EACCES) {
        SYSLOG("no access for config file");
    }
    if (fp == NULL) return;

    while(fgets(buffer, 1024, fp)) {

        if((eq = strchr(buffer, '='))) {
            end = eq - 1;
            val = eq + 1;
            while(end > buffer && isspace(*end)) end--;
            end++;
            *end = '\0';

            while(*val && isspace(*val)) val++;

            eq = val;
            while(*eq != '\0') eq++;
            eq--;

            while(*eq == '\n') {
                *eq = '\0';
                eq--;
            }
        } else val = NULL;

        if(!strcmp(buffer, "auth_query")) {
            options->query_auth = strdup(val);
        } else if( strcmp(buffer, "connect") == 0 ) {
            options->connstr = strdup(val);
        } else if(!strcmp(buffer, "auth_succ_query")) {
            options->query_auth_succ = strdup(val);
        } else if(!strcmp(buffer, "auth_fail_query")) {
            options->query_auth_fail = strdup(val);
        } else if(!strcmp(buffer, "acct_query")) {
            options->query_acct = strdup(val);
        } else if(!strcmp(buffer, "pwd_query")) {
            options->query_pwd = strdup(val);
        } else if(!strcmp(buffer, "session_open_query")) {
            options->query_session_open = strdup(val);
        } else if(!strcmp(buffer, "session_close_query")) {
            options->query_session_close = strdup(val);
        } else if(!strcmp(buffer, "database")) {
            options->db = strdup(val);
        } else if(!strcmp(buffer, "table")) {
            options->table = strdup(val);
        } else if(!strcmp(buffer, "host")) {
            options->host = strdup(val);
        } else if(!strcmp(buffer, "port")) {
            options->port = strdup(val);
        } else if(!strcmp(buffer, "timeout")) {
            options->timeout = strdup(val);
        } else if(!strcmp(buffer, "user")) {
            options->user = strdup(val);
        } else if(!strcmp(buffer, "sslmode")) {

            /* If not a valid option */
            if(strcmp(val, "require") != 0 && strcmp(val, "prefer") != 0 && strcmp(val, "allow") != 0 && strcmp(val,"disable") != 0) {
                SYSLOG("sslmode \"%s\" is not a valid option! Falling back to \"prefer\".", val);
                options->sslmode = strdup("prefer");
            } else
                options->sslmode = strdup(val);
        } else if(!strcmp(buffer, "password")) {
            options->passwd = strdup(val);
        } else if(!strcmp(buffer, "user_column")) {
            options->column_user = strdup(val);
        } else if(!strcmp(buffer, "pwd_column")) {
            options->column_pwd = strdup(val);
        } else if(!strcmp(buffer, "expired_column")) {
            options->column_expired = strdup(val);
        } else if(!strcmp(buffer, "newtok_column")) {
            options->column_newpwd = strdup(val);
        } else if(!strcmp(buffer, "pw_type")) {
            options->pw_type = PW_CLEAR;
            if(!strcmp(val, "md5")) {
                options->pw_type = PW_MD5;
            } else if(!strcmp(val, "sha1")) {
                options->pw_type = PW_SHA1;
            } else if(!strcmp(val, "crypt")) {
                options->pw_type = PW_CRYPT;
            } else if(!strcmp(val, "crypt_md5")) {
                options->pw_type = PW_CRYPT_MD5;
            } else if(!strcmp(val, "md5_postgres")) {
                options->pw_type = PW_MD5_POSTGRES;
            }
        } else if(!strcmp(buffer, "debug")) {
            options->debug = 1;
        }

    }

    fclose(fp);

    return;
}

modopt_t * mod_options(int argc, const char **argv) {

    int i,force=0;
    char *ptr,*value;
    modopt_t * modopt = (modopt_t *)malloc(sizeof(modopt_t));

    struct opttab {
        const char name[16];
        int value;
    };
    static const struct opttab std_options[] = {
        { "debug",          PAM_OPT_DEBUG },
        { "no_warn",        PAM_OPT_NO_WARN },
        { "authtok",         PAM_OPT_USE_FIRST_PASS },
        { "use_authtok",    PAM_OPT_USE_FIRST_PASS },
        { "use_first_pass", PAM_OPT_USE_FIRST_PASS },
        { "try_first_pass", PAM_OPT_TRY_FIRST_PASS },
        { "use_mapped_pass",PAM_OPT_USE_MAPPED_PASS },
        { "echo_pass",      PAM_OPT_ECHO_PASS },
        { "",         0 }
    };
    const struct opttab *p;

    /* Initializing values */
    modopt->connstr = NULL;
    modopt->db = NULL;
    modopt->host = NULL;
    modopt->user = NULL;
    modopt->table = NULL;
    modopt->passwd = NULL;
    modopt->pw_type = PW_SHA1;
    modopt->sslmode = strdup("prefer");
    modopt->timeout = NULL;
    modopt->fileconf = NULL;
    modopt->column_pwd = NULL;
    modopt->column_user = NULL;
    modopt->column_expired = NULL;
    modopt->column_newpwd = NULL;
    modopt->query_acct = NULL;
    modopt->query_pwd = NULL;
    modopt->query_auth = NULL;
    modopt->query_auth_succ = NULL;
    modopt->query_auth_fail = NULL;
    modopt->query_session_open = NULL;
    modopt->query_session_close = NULL;
    modopt->port = strdup("5432");
    modopt->debug = 0;
    modopt->std_flags = 0;

    for(i=0; i<argc; i++) {

        for (p = std_options; p->name[0] != '\0'; p++) {
            if (strcmp(argv[i], p->name) == 0) {
                modopt->std_flags |= p->value;
                break;
            }
        }

        ptr = strchr(argv[i], '=');
        if(ptr != NULL) {

            char *option;
            option = strndup(argv[i], ptr-argv[i]);
            value = strndup(ptr+1, strchr(argv[i],'\0')-ptr);

            if( strcmp(option, "host") == 0 ) {
                modopt->host = strdup(value);
            } else if( strcmp(option, "config_file") == 0 ) {
                modopt->fileconf = strdup(value);
            } else if( strcmp(option, "database") == 0 ) {
                modopt->db = strdup(value);
            } else if( strcmp(option, "table") == 0 ) {
                modopt->table = strdup(value);
            } else if( strcmp(option, "user") == 0 ) {
                modopt->user = strdup(value);
            } else if( strcmp(option, "password") == 0 ) {
                modopt->passwd = strdup(value);
            } else if( strcmp(option, "sslmode") == 0 ) {

                /* If not a valid option */
                if(strcmp(value, "require") != 0 && strcmp(value, "prefer") != 0 && strcmp(value, "allow") != 0 && strcmp(value,"disable") != 0) {
                    SYSLOG("sslmode \"%s\" is not a valid option! Falling back to \"prefer\".", value);
                    modopt->sslmode = strdup("prefer");
                } else
                    modopt->sslmode = strdup(value);

            } else if( strcmp(option, "debug") == 0 ) {
                modopt->debug = atoi(value);
            } else if( strcmp(option, "port") == 0 ) {
                modopt->port = strdup(value);
            }

        } else {

            if( strcmp(argv[i], "fileconf") == 0 ) {
                modopt->fileconf = strdup(PAM_PGSQL_FILECONF);
            } else if( strcmp(argv[i], "force") == 0 ) {
                force = 1;
            }

        }

    }

    /* Setting password in the module options is unsafe */
    if(force == 0 && modopt->passwd != NULL) {
        SYSLOG("You cannot set the password in the module options, it's unsafe! If you know what you're doing use \"force\" in the options.");
        free(modopt->passwd);
        modopt->passwd = NULL;
    }

    if(modopt->fileconf == NULL)
        modopt->fileconf = strdup(PAM_PGSQL_FILECONF);

    read_config_file(modopt);

    /*
     * If the required queries are no given by the user
     * we create a default one based the given table and columns
     */
    if(modopt->query_auth == NULL) {

        if(modopt->column_pwd != NULL && modopt->table != NULL && modopt->column_user != NULL) {

            modopt->query_auth = (char *) malloc(32+strlen(modopt->column_pwd)+strlen(modopt->table)+strlen(modopt->column_user));
            sprintf(modopt->query_auth, "select %s from %s where %s = %%u", modopt->column_pwd, modopt->table, modopt->column_user);

        } else {
            SYSLOG("Can't build auth query");
        }

    }

    if(modopt->query_acct == NULL) {

        if(modopt->column_expired != NULL && modopt->column_pwd != NULL && modopt->column_newpwd != NULL && modopt->table != NULL && modopt->column_user != NULL) {

            modopt->query_acct = (char *) malloc(96+2*strlen(modopt->column_pwd)+strlen(modopt->table)+strlen(modopt->column_user)+2*strlen(modopt->column_expired)+2*strlen(modopt->column_newpwd));
            sprintf(modopt->query_acct, "select (%s = 'y' OR %s = '1'), (%s = 'y' OR %s = '1'), (%s IS NULL OR %s = '') from %s where %s = %%u", modopt->column_expired,  modopt->column_expired, modopt->column_newpwd, modopt->column_newpwd, modopt->column_pwd, modopt->column_pwd, modopt->table, modopt->column_user);

            /* Expired column is null */
        } else if(modopt->column_pwd != NULL && modopt->column_newpwd != NULL && modopt->table != NULL && modopt->column_user != NULL) {

            modopt->query_acct = (char *) malloc(96+2*strlen(modopt->column_pwd)+strlen(modopt->table)+strlen(modopt->column_user)+2*strlen(modopt->column_newpwd));
            sprintf(modopt->query_acct, "select false, (%s = 'y' OR %s = '1'), (%s IS NULL OR %s = '') from %s where %s = %%u", modopt->column_newpwd, modopt->column_newpwd, modopt->column_pwd, modopt->column_pwd, modopt->table, modopt->column_user);

            /* Newpwd column is null */
        } else if(modopt->column_expired != NULL && modopt->column_pwd != NULL && modopt->table != NULL && modopt->column_user != NULL) {

            modopt->query_acct = (char *) malloc(96+2*strlen(modopt->column_pwd)+strlen(modopt->table)+strlen(modopt->column_user)+2*strlen(modopt->column_expired));
            sprintf(modopt->query_acct, "select (%s = 'y' OR %s = '1'), false, (%s IS NULL OR %s = '') from %s where %s = %%u", modopt->column_newpwd, modopt->column_newpwd, modopt->column_pwd, modopt->column_pwd, modopt->table, modopt->column_user);

        }

    }

    if(modopt->query_pwd == NULL) {

        if(modopt->column_pwd != NULL && modopt->table != NULL && modopt->column_user != NULL) {

            modopt->query_pwd = (char *) malloc(40+strlen(modopt->column_pwd)+strlen(modopt->table)+strlen(modopt->column_user));
            sprintf(modopt->query_pwd, "update %s set %s = %%p where %s = %%u", modopt->table, modopt->column_pwd, modopt->column_user);

        }

    }

    return modopt;

}


static void free_mod_options(modopt_t *options) {

    if(options == NULL)
        return;


    return;

}
