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

SECStatus
Fill_CK_ATTRIBUTE_Data(CK_ATTRIBUTE_PTR ptr, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value) {
    if (!ptr) {
        return SECFailure;
    }
    ptr->type= type;
    ptr->pValue = value;
    ptr->ulValueLen = sizeof(value);
    return SECSuccess;
}


SECStatus
PK11_GetCertURI(CERTCertificate *cert) {
    P11KitUri URI;
    int st, uristatus;
    SECStatus rv;
    SECStatus flag;
    CK_TOKEN_INFO *tokeninfo;
    PK11SlotInfo *slot = NULL;
    CK_ATTRIBUTE_PTR id;
    CK_ATTRIBUTE_PTR object;
    CK_ATTRIBUTE_PTR type;
    char *string;

    uri = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    slot = cert->slot;
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(uri));
    if (rv == SECFailure) {
        p11_kit_uri_free(uri);
        return SECFailure;
    }
    /*
    Assigning the attributes of the CK_ATTRIBUTE Pointers
    */

    /*
    Setting values using external functions
    flag = Fill_CK_ATTRIBUTE_Data(id, CKA_ID, cert->subjectKeyID);
    flag = Fill_CK_ATTRIBUTE_Data(object, CKA_LABEL, cert->nickname);
    flag = Fill_CK_ATTRIBUTE_Data(type, CKA_CLASS, CKO_CERTIFICATE);
    */

    /*
    Better to use a function to set attributes.Once attribute assignment
    verified, will switch to the external function
    */
    id->type = CKA_ID;
    id->pValue = cert->subjectKeyID;
    id->ulValueLen = sizeof(cert->subjectKeyID);
    
    object->type = CKA_LABEL;
    object->pValue = cert->nickname;
    object->ulValueLen = sizeof(cert->nickname);

    type->type=CKA_CLASS;
    type->pValue = CKO_CERTIFICATE;
    type->ulValueLen = sizeof(CKO_CERTIFICATE);
    
    st = p11_kit_uri_set_attribute(&URI, id) && 
         p11_kit_uri_set_attribute(&URI, object) && 
         p11_kit_uri_set_attribute(&URI, type);
    if (st != P11_KIT_URI_OK) {
        return SECFailure;
    }
    uristatus = p11_kit_uri_format(&URI, P11_KIT_URI_FOR_OBJECT, &string)
    if (uristatus == P11_KIT_URI_OK) {
        printf("%s\n", string);
        return SECSuccess;
    }
    return SECFailure;
}   
