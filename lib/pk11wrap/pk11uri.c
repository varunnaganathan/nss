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
    if (slot->uri) {
        PK11_ExitSlotMonitor(slot);
        return slot->uri;
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
    slot->uri = result;
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
    SECMOD_ReleaseReadLock(moduleLock);

    SECMOD_GetWriteLock(moduleLock);
    uri = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        SECMOD_ReleaseWriteLock(moduleLock);
        return NULL;
    }
    
    moduleinfo = p11_kit_uri_get_module_info(uri);
    SECMOD_ReleaseWriteLock(moduleLock);
    //This fills the module info into the CK_INFO_PTR passed
    status = PK11_GetModInfo(module, moduleinfo);
    if (status == SECFailure) {
        return NULL;
    }

    SECMOD_GetWriteLock(moduleLock);
    // Format the uri to string form
    int uristatus = p11_kit_uri_format(uri, P11_KIT_URI_FOR_MODULE, &string);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        p11_kit_uri_free(uri);
        SECMOD_ReleaseWriteLock(moduleLock);
        return NULL;
    } else {
        printf("%s\n", string);
        module->uri = string;
        p11_kit_uri_free(uri);
        SECMOD_ReleaseWriteLock(moduleLock);
        return module->uri;
    }
}

char *
PK11_GetCertURI(CERTCertificate *cert) {
    P11KitUri *uri;
    int st, uristatus;
    SECStatus rv;
    PK11SlotInfo *slot = NULL;
    char *string;
    CK_OBJECT_CLASS class = CKO_CERTIFICATE;

    /* Confirm if this is the right locking function */
    CERT_LockCertRefCount(cert);
    if (cert->uri) {
        CERT_UnlockCertRefCount(cert);
        return cert->uri;
    }

    uri = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    }
    
    slot = cert->slot;
    
    CERT_UnlockCertRefCount(cert);
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(uri));
    CERT_LockCertRefCount(cert);
    
    if (rv == SECFailure) {
        p11_kit_uri_free(uri);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    }
    
    /* Setting values of the attributes */
    CK_ATTRIBUTE id = {CKA_ID, (cert->subjectID.data), cert->subjectID.len };
    CK_ATTRIBUTE object = {CKA_LABEL, &cert->nickname, sizeof(cert->nickname) };
    CK_ATTRIBUTE type = {CKA_CLASS, &class, sizeof(class) };
    
    st = p11_kit_uri_set_attribute(uri, &id) && 
         p11_kit_uri_set_attribute(uri, &object) && 
         p11_kit_uri_set_attribute(uri, &type);
    if (st != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        p11_kit_uri_free(uri);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    }

    uristatus = p11_kit_uri_format(uri, P11_KIT_URI_FOR_OBJECT, &string);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        p11_kit_uri_free(uri);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    } 
    cert->uri = string;
    printf("%s\n", string);
    p11_kit_uri_free(uri);
    CERT_UnlockCertRefCount(cert);
    return string;
}

char *
PK11_GetPrivateKeyURI(SECKEYPrivateKey *key) {
    P11KitUri *URI;
    int st, uristatus;
    SECStatus rv;
    PK11SlotInfo *slot = NULL;
    char *string;
    SECItem result;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;

    /* Find the appropriate locking function for a Private key */
    if (key->uri) {
        return key->uri;
    }

    URI = p11_kit_uri_new();
    if (!URI) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    slot = key->pkcs11Slot;
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(URI));
    if (rv == SECFailure) {
        p11_kit_uri_free(URI);
        return NULL;
    }
    /* Get the SECItem for the CKA_LABEL of the key */
    rv = PK11_ReadAttribute(key->pkcs11Slot, key->pkcs11ID, CKA_LABEL, NULL, &result);
    
    /* Assign the attributes of the URI */
    CK_ATTRIBUTE id = { CKA_ID, &(key->pkcs11ID), sizeof(key->pkcs11ID) };
    CK_ATTRIBUTE object = { CKA_LABEL, result.data, result.len };    
    CK_ATTRIBUTE type = { CKA_CLASS, &class, sizeof(class) };
    
    st = p11_kit_uri_set_attribute(URI, &id) && 
         p11_kit_uri_set_attribute(URI, &object) && 
         p11_kit_uri_set_attribute(URI, &type);
    if (st != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        p11_kit_uri_free(URI);
        return NULL;
    }
    uristatus = p11_kit_uri_format(URI, P11_KIT_URI_FOR_OBJECT, &string);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        p11_kit_uri_free(URI);
        return NULL;
    } else {
        key->uri = string;
        printf("%s\n", string);
        p11_kit_uri_free(URI);
        return string;
    }
}
