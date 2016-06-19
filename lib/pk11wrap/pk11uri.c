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
    int status;

    PK11_EnterSlotMonitor(slot);
    //Confirm that this is the token we actually need and not some other token
    if (slot->nssToken->uri) {
        PK11_ExitSlotMonitor(slot);
        return slot->nssToken->uri;
    }
    uri = p11_kit_uri_new();
    if (!uri) {
	    PORT_SetError(SEC_ERROR_NO_MEMORY);
        PK11_ExitSlotMonitor(slot);
	    return NULL;
    }
    
    //Have to unlock to call PK11_GetTokenInfo
    PK11_ExitSlotMonitor(slot);
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(uri));
    PK11_EnterSlotMonitor(slot);
    if (rv == SECFailure) {
	    p11_kit_uri_free(uri);
        PK11_ExitSlotMonitor(slot);
	    return NULL;
    }
    status = p11_kit_uri_format(uri, P11_KIT_URI_FOR_TOKEN, &result); 
    if (status != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(status));
	    result = NULL;
    }
    //Set the uri for the token struct 
    slot->nssToken->uri = result;
    p11_kit_uri_free(uri);
    PK11_ExitSlotMonitor(slot);
    return result;
}


char *
PK11_GetModuleURI(SECMODModule *module) {
    P11KitUri *uri;
    CK_INFO *moduleinfo = NULL;
    char *string = NULL;
    SECStatus status;
    SECMODListLock *moduleLock = NULL;

    moduleLock = SECMOD_GetDefaultModuleListLock();
    if (!moduleLock) {
        PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
        return NULL;
    }
    SECMOD_GetReadLock(moduleLock);
    if (module->uri) {
        SECMOD_ReleaseReadLock(moduleLock);
        return module->uri;
    }

    uri = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        SECMOD_ReleaseReadLock(moduleLock);
        return NULL;
    }
    
    moduleinfo = p11_kit_uri_get_module_info(uri);
    SECMOD_ReleaseReadLock(moduleLock);
    //This fills the module info into the CK_INFO_PTR passed
    status = PK11_GetModInfo(module, moduleinfo);
    if (status == SECFailure) {
        return NULL;
    }

    SECMOD_GetReadLock(moduleLock);
    // Format the uri to string form
    int uristatus = p11_kit_uri_format(uri, P11_KIT_URI_FOR_MODULE, &string);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        p11_kit_uri_free(uri);
        SECMOD_ReleaseReadLock(moduleLock);
        return NULL;
    } else {
        printf("%s\n", string);
        module->uri = string;
        p11_kit_uri_free(uri);
        SECMOD_ReleaseReadLock(moduleLock);
        return module->uri;
    }
}

/*
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
    
    //Assigning the attributes of the CK_ATTRIBUTE Pointers

    //Setting values using external functions
    
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_ID, (cert->subjectID.data), cert->subjectID.len);
    flag = Fill_CK_ATTRIBUTE_Data(&object, CKA_LABEL, &cert->nickname, sizeof(cert->nickname));
    flag = Fill_CK_ATTRIBUTE_Data(&type, CKA_CLASS, &class, sizeof(class));
    if (flag == SECFailure) {
        return SECFailure;
    }
    
    //Better to use a function to set attributes.Once attribute assignment
    //verified, will switch to the external function
    
  
    st = p11_kit_uri_set_attribute(uri, &id) && 
         p11_kit_uri_set_attribute(uri, &object) && 
         p11_kit_uri_set_attribute(uri, &type);
    if (p11ToNSSError(st) != 0) {
        PORT_SetError(p11ToNSSError(st));
        p11_kit_uri_free(uri);
        return SECFailure;
    }

    uristatus = p11_kit_uri_format(uri, P11_KIT_URI_FOR_OBJECT, &string);
    if (p11ToNSSError(uristatus) != 0) {
        PORT_SetError(p11ToNSSError(uristatus));
        p11_kit_uri_free(uri);
        return SECFailure;
    } else {
        if (!cert->uri) {
            cert->uri = string;
        }
        printf("%s\n", string);
        p11_kit_uri_free(uri);
        return SECSuccess;
    }
    
    p11_kit_uri_free(uri);
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
    SECItem result;
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
    //Get the SECItem for the CKA_LABEL of the key
    
    rv = PK11_ReadAttribute(key->pcks11Slot, key->pkcs11ID, CKA_LABEL, NULL, &result);
    
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_ID, &(key->pkcs11ID), sizeof(key->pkcs11ID));
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_LABEL, result.data, result.len);    
    flag = Fill_CK_ATTRIBUTE_Data(&id, CKA_CLASS, &class, sizeof(class));
    if (flag == SECFailure) {
        PORT_SetError(SEC_ERROR_BAD_DATA);
        p11_kit_uri_free(URI);
        return SECFailure;
    }    

    st = p11_kit_uri_set_attribute(URI, &id) && 
         p11_kit_uri_set_attribute(URI, &object) && 
         p11_kit_uri_set_attribute(URI, &type);
    if (p11ToNSSError(st) != 0) {
        PORT_SetError(p11ToNSSError(st));
        p11_kit_uri_free(URI)
        return SECFailure;
    }
    uristatus = p11_kit_uri_format(URI, P11_KIT_URI_FOR_OBJECT, &string);
    if (p11ToNSSError(uristatus) != 0) {
        PORT_SetError(p11ToNSSError(uristatus));
        p11_kit_uri_free(URI);
        return SECFailure;
    } else {
        printf("%s\n", string);
        p11_kit_uri_free(URI);
        return SECSuccess;
    }
    
    p11_kit_uri_free(URI);
    return SECFailure;
}
*/