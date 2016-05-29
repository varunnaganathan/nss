/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * Deal with PKCS #11 Slots.
 */
#include "seccomon.h"
#include "secmod.h"
#include "nssilock.h"
#include "secmodi.h"
#include "secmodti.h"
#include "pkcs11t.h"
#include "pk11func.h"
#include "secitem.h"
#include "secerr.h"

#include "dev.h" 
#include "dev3hack.h" 
#include "pkim.h"
#include "utilpars.h"

/* Prevent p11-kit from including its own pkcs11.h */
#define PKCS11_H 1
#include <p11-kit/uri.h>


char *
PK11_GetTokenUri(PK11SlotInfo *slot)
{
    SECStatus rv;
    P11KitUri *uri;
    char *result;

    uri = p11_kit_uri_new();
    if (!uri) {
	    PORT_SetError(SEC_ERROR_NO_MEMORY);
	    return NULL;
    }
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(uri));
    if (rv == SECFailure) {
	    p11_kit_uri_free(uri);
	    return NULL;
    }
    if (p11_kit_uri_format(uri, P11_KIT_URI_FOR_TOKEN, &result)) {
	    /*
        * PORT_SetError(WTF?);
        */
	    result = NULL;
    }
    p11_kit_uri_free(uri);
    return result;
}

SECStatus
PK11_GetModuleURI(SECMODModule *module) {
    P11KitUri *uri = p11_kit_uri_new();
    CK_INFO *moduleinfo = p11_kit_uri_get_module_info(uri);
    char *string = NULL;
    SECStatus status;

    /*
    * This fills the module info into the CK_INFO_PTR passed
    */
    status = PK11_GetModInfo(module, moduleinfo);
    if (status == SECFailure) {
        return SECFailure;
    }
    /*
    * Format the uri to string form
    */
    int uristatus = p11_kit_uri_format(uri, P11_KIT_URI_FOR_MODULE, &string);
    if(uristatus == P11_KIT_URI_OK) {
        printf("%s\n", string);
        return SECSuccess;
    }
    return SECFailure;
}
