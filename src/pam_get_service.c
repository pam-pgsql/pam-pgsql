/*
 * Copyright (c) 2000. Leon Breedt, Copyright (c) 2002 David D.W. Downey
 */

/* $Id: pam_get_service.c,v 1.2 2000/06/25 10:01:41 ljb Exp $ */
#include <security/pam_modules.h>
#include <stdlib.h>

const char *pam_get_service(pam_handle_t *pamh)
{
    const char *service = NULL;

	if(pam_get_item(pamh, PAM_SERVICE, (void *) &service) != PAM_SUCCESS)
        return NULL;
    return service;
}
