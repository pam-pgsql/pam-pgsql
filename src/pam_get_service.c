/*
 * Copyright (c) 2000. Leon Breedt, 
 *               2002 David D.W. Downey
 *               2009 William Grzybowski <william@agencialivre.com.br>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <security/pam_modules.h>

const char *
pam_get_service(pam_handle_t *pamh)
{

	const char *service = NULL;

	if(pam_get_item(pamh, PAM_SERVICE, (void *) &service) != PAM_SUCCESS)
		return NULL;

	return service;

}
