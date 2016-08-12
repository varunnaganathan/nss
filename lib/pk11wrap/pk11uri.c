/* This Source Code Form is subject to the terms of the Mozilla Public
+ * License, v. 2.0. If a copy of the MPL was not distributed with this
+ * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
+ * Deal with PKCS #11 Slots.
+ */
#include "seccomon.h"
#include "secmod.h"
#include "nssilock.h"
#include "secmodi.h"
#include "secmodti.h"
#include "pkcs11t.h"
#include "pk11func.h"
#include "secitem.h"
#include "secerr.h"
#include "nssrwlk.h"
#include "keyhi.h"

#include "dev.h" 
#include "dev3hack.h" 
#include "pkim.h"
#include "utilpars.h"
#include "pki3hack.h"

#include "p11uri.h"



SECMODModule *SECMOD_FindModuleByUri(char *uri)
{
    P11KitUri *URI;
    SECMODModuleList *listnode;
    SECMODModule *module = NULL;
    int st;
    SECStatus status;
    CK_INFO moduleinfo;
    SECMODListLock *moduleLock = NULL;
    SECMODModuleList *modules = NULL;

    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    st = P11URI_parse(uri, P11URI_FOR_MODULE, URI);
    if (st != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        return NULL;
    }

    moduleLock = SECMOD_GetDefaultModuleListLock();
    if (!moduleLock) {
        PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
        return module;
    }
    modules = SECMOD_GetDefaultModuleList();
    if (!modules) {
        PORT_SetError(SEC_ERROR_NO_MODULE);
        return module;
    }
    SECMOD_GetReadLock(moduleLock);
    for(listnode =  modules; listnode != NULL; listnode = listnode->next) {
        SECMOD_ReleaseReadLock(moduleLock);
        status = PK11_GetModInfo(listnode->module, &moduleinfo);
        SECMOD_GetReadLock(moduleLock);
        if (status != SECSuccess) {
            SECMOD_ReleaseReadLock(moduleLock);
            return NULL;
        }
        if (P11URI_match_module_info(URI, &moduleinfo) == 1) {
            module = listnode->module;
            break;
        }
        
    }
    SECMOD_ReleaseReadLock(moduleLock);
    if(!module) {
        return (SECMODModule *)NULL;
    }
    return module;
}



//2nd version similar to NSSTrustDomain_FindTokenByName
NSS_IMPLEMENT NSSToken *
NSSTrustDomain_FindTokenByUri(NSSTrustDomain *td, char *uri)
{
    int st;
    P11KitUri *URI;
    NSSToken *tok = NULL;
    SECStatus status;
    PK11SlotInfo *slotinfo;
    CK_TOKEN_INFO tokeninfo;

    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }
    st = P11URI_parse(uri, P11URI_FOR_TOKEN, URI);
    if(st != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        P11URI_free(URI);
        return NULL;
    }
    NSSRWLock_LockRead(td->tokensLock);
    for (tok  = (NSSToken *)nssListIterator_Start(td->tokens);
         tok != (NSSToken *)NULL;
         tok  = (NSSToken *)nssListIterator_Next(td->tokens))
    {
        if (nssToken_IsPresent(tok)) {
            slotinfo = tok->pk11slot;
            
            //Have to unlock to call PK11_GetTokenInfo
            
            NSSRWLock_UnlockRead(td->tokensLock);
            status = PK11_GetTokenInfo(slotinfo, &tokeninfo);
            NSSRWLock_LockRead(td->tokensLock);
            if(status == SECFailure) {
                //Raise error
            }
            if (P11URI_match_token_info(URI, &tokeninfo) == 1)
            {
                break;
            }
        }
    }
    nssListIterator_Finish(td->tokens);
    NSSRWLock_UnlockRead(td->tokensLock);
    P11URI_free(URI);
    return tok;
}


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
    uri = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        PK11_ExitSlotMonitor(slot);
        return NULL;
    }
    
    //Have to unlock to call PK11_GetTokenInfo
    PK11_ExitSlotMonitor(slot);
    rv = PK11_GetTokenInfo(slot, P11URI_get_token_info(uri));
    PK11_EnterSlotMonitor(slot);
    if (rv == SECFailure) {
        P11URI_free(uri);
        PK11_ExitSlotMonitor(slot);
        return NULL;
    }
    status = P11URI_format(uri, P11URI_FOR_TOKEN, &result); 
    if (status != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(status));
        result = NULL;
    }
    //Set the uri for the token struct 
    slot->uri = result;
    P11URI_free(uri);
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
    uri = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        SECMOD_ReleaseWriteLock(moduleLock);
        return NULL;
    }
    
    moduleinfo = P11URI_get_module_info(uri);
    SECMOD_ReleaseWriteLock(moduleLock);
    //This fills the module info into the CK_INFO_PTR passed
    status = PK11_GetModInfo(module, moduleinfo);
    if (status == SECFailure) {
        return NULL;
    }

    SECMOD_GetWriteLock(moduleLock);
    // Format the uri to string form
    int uristatus = P11URI_format(uri, P11URI_FOR_MODULE, &string);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        P11URI_free(uri);
        SECMOD_ReleaseWriteLock(moduleLock);
        return NULL;
    } else {
        printf("%s\n", string);
        module->uri = string;
        P11URI_free(uri);
        SECMOD_ReleaseWriteLock(moduleLock);
        return module->uri;
    }
}

//Similar to CERT_FindCertByKeyID
/*
CERTCertificate *
CERT_FindCertByURI(CERTCertDBHandle *handle, SECItem *name, char *uri) {
    
    P11KitUri *URI;
    int uristatus;
    CERTCertList *list;
    CERTCertificate *cert = NULL;
    CERTCertListNode *node, *head;
    CK_ATTRIBUTE_PTR id;
    CK_ATTRIBUTE_PTR object;
    CK_ATTRIBUTE_PTR type;

    CK_ATTRIBUTE ID = {CKA_ID, NULL, 0};    
    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }
    // Check the URI param being passed 
    uristatus = P11URI_parse(uri, P11URI_FOR_OBJECT, URI);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        P11URI_free(URI);
        return (CERTCertificate *)NULL;
    }

    id = P11URI_get_attribute(URI,CKA_ID);
    object = P11URI_get_attribute(URI,CKA_LABEL);
    type = P11URI_get_attribute(URI,CKA_CLASS);

    if( !id || !object || !type) {
        PORT_SetError(SEC_ERROR_CERT_NO_RESPONSE);
        P11URI_free(URI);
        return (CERTCertificate *)NULL;
    }

    list = CERT_CreateSubjectCertList(NULL, handle, name, 0, PR_FALSE);
    if (list == NULL) {
        P11URI_free(URI);
        return (CERTCertificate *)NULL;
    }
    
    node = head = CERT_LIST_HEAD(list);
    if (head) {
        do {
            if (PK11_GetAttributes(NULL, node->cert->slot, node->cert->pkcs11ID, &ID, 1) != CKR_OK) {
                return NULL;
            }
//            if (node->cert && (!PORT_Strcmp((const char *)node->cert->subjectKeyID.data, (const char *)id->pValue)) &&
            if (node->cert && (!PORT_Strcmp((const char *)ID.pValue, (const char *)id->pValue)) &&
                (!PORT_Strcmp(node->cert->nickname, object->pValue))) {
                cert = CERT_DupCertificate(node->cert);
                goto done;
            }
            
            node = CERT_LIST_NEXT(node);  
        } while (node && head != node);
    }
    PORT_SetError(SEC_ERROR_UNKNOWN_ISSUER);
done:
    if (list) {
        CERT_DestroyCertList(list);
    }
    P11URI_free(URI);
    return cert;
}*/



//SECOND VERSION
CK_OBJECT_HANDLE *CERT_FindCertByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
    P11KitUri *URI;
    //CK_ATTRIBUTE attrs[3];
    int uristatus, objcount;
    //CK_ATTRIBUTE_PTR Id, Object;
    CK_ATTRIBUTE_PTR attributes;
    CK_ULONG numattrs, i;
    //CK_OBJECT_CLASS certclass = CKO_CERTIFICATE;
    CK_ATTRIBUTE *theTemplate;
    CK_OBJECT_HANDLE *peerID;

    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = P11URI_parse(uri, P11URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = P11URI_get_attributes(URI,&numattrs);
    theTemplate = PORT_Alloc(sizeof(CK_ATTRIBUTE)*numattrs);
    for (i=0; i<numattrs; i++) {
        CK_ATTRIBUTE temp =  {attributes[i].type, attributes[i].pValue, attributes[i].ulValueLen};
        theTemplate[i] = temp;
    }
    peerID = pk11_FindObjectsByTemplate(slot, theTemplate, numattrs, &objcount);
    free(theTemplate);
    return peerID;

}





char *
PK11_GetCertURI(CERTCertificate *cert, void *wincx) {
    P11KitUri *uri;
    int st, uristatus;
    SECStatus rv;
    PK11SlotInfo *slot = NULL;
    char *string;
    CK_OBJECT_CLASS class = CKO_CERTIFICATE;
    CK_OBJECT_HANDLE certHandle;

    /* Confirm if this is the right locking function */
    CERT_LockCertRefCount(cert);
    if (cert->uri) {
        CERT_UnlockCertRefCount(cert);
        return cert->uri;
    }

    uri = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    }
    
    slot = cert->slot;
    if (!slot) {
        certHandle = PK11_FindObjectForCert(cert, wincx, &slot);
        if (certHandle != CK_INVALID_HANDLE)
            PORT_SetError(SEC_ERROR_PKCS11_FUNCTION_FAILED);
            return NULL;
    }

    
    CERT_UnlockCertRefCount(cert);
    rv = PK11_GetTokenInfo(slot, P11URI_get_token_info(uri));
    CERT_LockCertRefCount(cert);
    
    if (rv == SECFailure) {
        P11URI_free(uri);
        CERT_UnlockCertRefCount(cert);
        return NULL;    
    }
    
    /* Setting values of the attributes */
    CK_ATTRIBUTE id = {CKA_ID, NULL, 0};
    CK_ATTRIBUTE object = {CKA_LABEL, cert->nickname, strlen(cert->nickname) };
    CK_ATTRIBUTE type = {CKA_CLASS, &class, sizeof(class) };

    if (PK11_GetAttributes(NULL, slot, cert->pkcs11ID, &id, 1) == CKR_OK)
        st = P11URI_set_attribute(uri, &id);
    else
        st = P11URI_OK;

    if (st != P11URI_OK ||
    (st = P11URI_set_attribute(uri, &type)) != P11URI_OK ||
    (st = P11URI_set_attribute(uri, &object)) != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        P11URI_free(uri);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    }

    uristatus = P11URI_format(uri, P11URI_FOR_OBJECT_ON_TOKEN, &string);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        P11URI_free(uri);
        CERT_UnlockCertRefCount(cert);
        return NULL;
    } 
    cert->uri = string;
    printf("%s\n", string);
    P11URI_free(uri);
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
    //  SECItem result;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;

    /* Find the appropriate locking function for a key */
    if (key->uri) {
        return key->uri;
    }

    URI = P11URI_new();
    if (!URI) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    slot = key->pkcs11Slot;
    rv = PK11_GetTokenInfo(slot, P11URI_get_token_info(URI));
    if (rv == SECFailure) {
        P11URI_free(URI);
        return NULL;
    }
    /* Get the SECItem for the CKA_LABEL of the key */
    //rv = PK11_ReadAttribute(key->pkcs11Slot, key->pkcs11ID, CKA_LABEL, NULL, &result);
    
    /* Assign the attributes of the URI */
    CK_ATTRIBUTE id = { CKA_ID, &(key->pkcs11ID), sizeof(key->pkcs11ID) };
    //CK_ATTRIBUTE object = { CKA_LABEL, result.data, result.len };    
    CK_ATTRIBUTE object = {CKA_LABEL, NULL, 0};
    CK_ATTRIBUTE type = { CKA_CLASS, &class, sizeof(class) };
    if (PK11_GetAttributes(NULL, slot, key->pkcs11ID, &object, 1) != CKR_OK) {
        return NULL;
    }
    
    if ((st = P11URI_set_attribute(URI, &id)) != P11URI_OK || 
        (st = P11URI_set_attribute(URI, &object)) != P11URI_OK || 
        (st =P11URI_set_attribute(URI, &type)) != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        P11URI_free(URI);
        return NULL;
    }

    uristatus = P11URI_format(URI, P11URI_FOR_OBJECT_ON_TOKEN, &string);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        P11URI_free(URI);
        return NULL;
    } else {
        key->uri = string;
        printf("%s\n", string);
        P11URI_free(URI);
        return string;
    }
}


NSSCertificate **
nssToken_FindObjectsByURI(NSSTrustDomain *td, char *uri)
{
  P11KitUri *URI;
    //CK_ATTRIBUTE attrs[3];
    int uristatus;
    //CK_ATTRIBUTE_PTR Id, Object;
    CK_ATTRIBUTE_PTR attributes;
    CK_ULONG numattrs;
    PK11SlotInfo *slot, *slotinfo;
    //CK_OBJECT_CLASS certclass = CKO_PRIVATE_KEY;
    //CK_ATTRIBUTE *attr = theTemplate;
    CK_TOKEN_INFO tokeninfo, *tinfo;
    NSSToken *token, *tok;
    nssCryptokiObject **objects;
    PRStatus status;
    nssPKIObjectCollection *collection;
    NSSCertificate **certs = NULL;

    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = P11URI_parse(uri, P11URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = P11URI_get_attributes(URI,&numattrs);
    tinfo = P11URI_get_token_info(URI);
    collection = nssCertificateCollection_Create(STAN_GetDefaultTrustDomain(), NULL);

    if (!tinfo) {
        slot = PK11_GetInternalKeySlot();
        token = PK11Slot_GetNSSToken(slot);
    }
    else {
        NSSRWLock_LockRead(td->tokensLock);
        for (tok  = (NSSToken *)nssListIterator_Start(td->tokens);
             tok != (NSSToken *)NULL;
             tok  = (NSSToken *)nssListIterator_Next(td->tokens))
        {
            if (nssToken_IsPresent(tok)) {
                slotinfo = tok->pk11slot;
                
                //Have to unlock to call PK11_GetTokenInfo
                
                NSSRWLock_UnlockRead(td->tokensLock);
                status = PK11_GetTokenInfo(slotinfo, &tokeninfo);
                NSSRWLock_LockRead(td->tokensLock);
                if (P11URI_match_token_info(URI, &tokeninfo) == 1)
                {
                    token = tok;
                    objects = find_objects_by_template(token, NULL,
                                       attributes, numattrs,
                                       0, &status);
                    nssPKIObjectCollection_AddInstances(collection, objects, 0);
                }
            }
        }
    }       
    certs = nssPKIObjectCollection_GetCertificates(collection, NULL, 0, NULL);
    nssPKIObjectCollection_Destroy(collection);
    return certs;
}




// SECOND VERSION
//Fails because the object doesnt exist in the uri
SECKEYPrivateKeyList *
PK11_FindPrivateKeyByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
    P11KitUri *URI;
    //CK_ATTRIBUTE attrs[3];
    int uristatus, objcount;
    //CK_ATTRIBUTE_PTR Id, Object;
    CK_ATTRIBUTE_PTR attributes;
    CK_ULONG numattrs, i;
    //CK_OBJECT_CLASS certclass = CKO_PRIVATE_KEY;
    //CK_ATTRIBUTE *attr = theTemplate;
    CK_OBJECT_HANDLE *peerID;
    SECKEYPrivateKeyList *keys;

    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = P11URI_parse(uri, P11URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = P11URI_get_attributes(URI,&numattrs);
    peerID = pk11_FindObjectsByTemplate(slot, attributes, numattrs, &objcount);
    //return peerID;
    // ADDING 
    keys = SECKEY_NewPrivateKeyList();
    if (keys == NULL) {
        PORT_Free(peerID);
        return NULL;
    }
    for (i=0; i < objcount ; i++) {
        SECKEYPrivateKey *privKey = 
            PK11_MakePrivKey(slot,nullKey,PR_TRUE,peerID[i],wincx);
        SECKEY_AddPrivateKeyToListTail(keys, privKey);
   }
   PORT_Free(peerID);
   return keys;
}

char *
PK11_GetPublicKeyURI(SECKEYPublicKey *key) {
    P11KitUri *URI;
    int st, uristatus;
    SECStatus rv;
    PK11SlotInfo *slot = NULL;
    char *string;
    SECItem result;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;

    /* Find the appropriate locking function for a key */
    if (key->uri) {
        return key->uri;
    }

    URI = P11URI_new();
    if (!URI) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    slot = key->pkcs11Slot;
    rv = PK11_GetTokenInfo(slot, P11URI_get_token_info(URI));
    if (rv == SECFailure) {
        P11URI_free(URI);
        return NULL;
    }
    /* Get the SECItem for the CKA_LABEL of the key */
    rv = PK11_ReadAttribute(key->pkcs11Slot, key->pkcs11ID, CKA_LABEL, NULL, &result);
    
    /* Assign the attributes of the URI */
    CK_ATTRIBUTE id = { CKA_ID, &(key->pkcs11ID), sizeof(key->pkcs11ID) };
    CK_ATTRIBUTE object = { CKA_LABEL, result.data, result.len };    
    CK_ATTRIBUTE type = { CKA_CLASS, &class, sizeof(class) };
    
    if ((st = P11URI_set_attribute(URI, &id)) != P11URI_OK || 
        (st = P11URI_set_attribute(URI, &object)) != P11URI_OK || 
        (st =P11URI_set_attribute(URI, &type)) != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        P11URI_free(URI);
        return NULL;
    }

    uristatus = P11URI_format(URI, P11URI_FOR_OBJECT_ON_TOKEN, &string);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        P11URI_free(URI);
        return NULL;
    } else {
        key->uri = string;
        printf("%s\n", string);
        P11URI_free(URI);
        return string;
    }
}

SECKEYPublicKeyList *
PK11_FindPublicKeyByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
    P11KitUri *URI;
    //CK_ATTRIBUTE attrs[3];
    int uristatus, objcount;
    //CK_ATTRIBUTE_PTR Id, Object;
    CK_ATTRIBUTE_PTR attributes;
    CK_ULONG numattrs, i;
    //CK_OBJECT_CLASS certclass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE *theTemplate;
    //CK_ATTRIBUTE *attr = theTemplate;
    CK_OBJECT_HANDLE *peerID;
    SECKEYPublicKeyList *keys;

    URI = P11URI_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = P11URI_parse(uri, P11URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = P11URI_get_attributes(URI,&numattrs);
    theTemplate = malloc(sizeof(CK_ATTRIBUTE)*numattrs);
    for (i=0; i<numattrs; i++) {
        CK_ATTRIBUTE temp =  {attributes[i].type, attributes[i].pValue, attributes[i].ulValueLen};
        theTemplate[i] = temp;
    }

    peerID = pk11_FindObjectsByTemplate(slot, theTemplate, numattrs, &objcount);
    PORT_Free(theTemplate);
    //return peerID;
    // ADDED
    keys = SECKEY_NewPublicKeyList();
    if (keys == NULL) {
        PORT_Free(peerID);
        return NULL;
    }
    for (i=0; i < objcount ; i++) {
        SECKEYPublicKey *pubKey = PK11_ExtractPublicKey(slot,nullKey,peerID[i]);
        if (pubKey) {
            SECKEY_AddPublicKeyToListTail(keys, pubKey);
        }
   }
   PORT_Free(peerID);
   return keys;
}

