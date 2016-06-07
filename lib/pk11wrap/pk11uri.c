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
Fill_CK_ATTRIBUTE_Data(CK_ATTRIBUTE_PTR ptr, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value,  CK_ULONG ulValueLen) {
    if (!ptr) {
        return SECFailure;
    }
    ptr->type= type;
    ptr->pValue = value;
    ptr->ulValueLen = ulValueLen;
    return SECSuccess;
}


SECStatus
PK11_GetCertURI(CERTCertificate *cert) {
    P11KitUri *uri;
    int st, uristatus;
    SECStatus rv;
    SECStatus flag;
    PK11SlotInfo *slot = NULL;
    CK_ATTRIBUTE id;
    CK_ATTRIBUTE object;
    CK_ATTRIBUTE type;
    char *string;
    CK_OBJECT_CLASS class = CKO_CERTIFICATE;


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
    */
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_ID, &cert->subjectID, sizeof(cert->subjectID));
    flag = Fill_CK_ATTRIBUTE_Data(&object, CKA_LABEL, &cert->nickname, sizeof(cert->nickname));
    flag = Fill_CK_ATTRIBUTE_Data(&type, CKA_CLASS, &class, sizeof(class));
    if (flag == SECFailure) {
        return SECFailure;
    }
    /*
    Better to use a function to set attributes.Once attribute assignment
    verified, will switch to the external function
    */
  
    st = p11_kit_uri_set_attribute(uri, &id) && 
         p11_kit_uri_set_attribute(uri, &object) && 
         p11_kit_uri_set_attribute(uri, &type);
    if (st != P11_KIT_URI_OK) {
        return SECFailure;
    }
    uristatus = p11_kit_uri_format(uri, P11_KIT_URI_FOR_OBJECT, &string);
    if (uristatus == P11_KIT_URI_OK) {
        printf("%s\n", string);
        return SECSuccess;
    }
    return SECFailure;
}   

SECStatus
PK11_GetPrivateKeyURI(SECKEYPrivateKey *key) {
    P11KitUri *URI;
    int st, uristatus;
    SECStatus rv;
    SECStatus flag;
    PK11SlotInfo *slot = NULL;
    CK_ATTRIBUTE id;
    CK_ATTRIBUTE object;
    CK_ATTRIBUTE type;
    char *string;
    char *nickname;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;


    URI = p11_kit_uri_new();
    if (!URI) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    slot = key->pkcs11Slot;
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(URI));
    if (rv == SECFailure) {
        p11_kit_uri_free(URI);
        return SECFailure;
    }
    nickname = PK11_GetObjectNickName(key->pkcs11Slot, key->pkcs11ID);
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_ID, &key->pkcs11ID, sizeof(key->pkcs11ID));
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_LABEL, &nickname, sizeof(nickname));    
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_CLASS, &class, sizeof(class));
    if (flag == SECFailure) {
        return SECFailure;
    }
    /*
    Better to use a function to set attributes.Once attribute assignment
    verified, will switch to the external function
    
    id.type = CKA_ID;
    id.pValue = key->pkcs11ID;
    id.ulValueLen = sizeof(key->pkcs11ID);
    
    object->type = CKA_LABEL;
    object->pValue = nickname;//Have to assign this
    object->ulValueLen = sizeof(nickname)//Have to assign this 

    type->type=CKA_CLASS;
    type->pValue = CKO_PRIVATE_KEY;
    type->ulValueLen = sizeof(CKO_PRIVATE_KEY);
    */

    st = p11_kit_uri_set_attribute(URI, &id) && 
         p11_kit_uri_set_attribute(URI, &object) && 
         p11_kit_uri_set_attribute(URI, &type);
    if (st != P11_KIT_URI_OK) {
        return SECFailure;
    }
    uristatus = p11_kit_uri_format(URI, P11_KIT_URI_FOR_OBJECT, &string);
    if (uristatus == P11_KIT_URI_OK) {
        printf("%s\n", string);
        return SECSuccess;
    }
    return SECFailure;
}