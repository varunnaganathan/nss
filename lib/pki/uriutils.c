/* 
Similar to SECMOD_FindModule.Added to pk11util.c
*/


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

    URI = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_MODULE, URI);
    if (st != P11_KIT_URI_OK)
    {
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
    for(listnode =  modules; listnode != NULL; listnode = listnode->next)
    {
        SECMOD_ReleaseReadLock(moduleLock);
        status = PK11_GetModInfo(listnode->module, &moduleinfo);
        SECMOD_GetReadLock(moduleLock);
        if (status != SECSuccess) {
            SECMOD_ReleaseReadLock(moduleLock);
            return NULL;
        }
        
        if (p11_kit_uri_match_module_info(URI, &moduleinfo) == 1) {
            module = listnode->module;
            break;
        }
        
    }
    SECMOD_ReleaseReadLock(moduleLock);
    if(!module)
    {
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

    URI = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }
    st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_TOKEN, URI);
    if(st != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(st));
        p11_kit_uri_free(URI);
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
            if (p11_kit_uri_match_token_info(URI, &tokeninfo) == 1)
            {
                break;
            }
        }
    }
    nssListIterator_Finish(td->tokens);
    NSSRWLock_UnlockRead(td->tokensLock);
    p11_kit_uri_free(URI);
    return tok;
}


//Similar to CERT_FindCertByKeyID
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

    URI = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }
    
    /* Check the URI param being passed */ 
    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT, URI);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        p11_kit_uri_free(URI);
        return (CERTCertificate *)NULL;
    }

    id = p11_kit_uri_get_attribute(URI,CKA_ID);
    object = p11_kit_uri_get_attribute(URI,CKA_LABEL);
    type = p11_kit_uri_get_attribute(URI,CKA_CLASS);

    if( !id || !object || !type) {
        PORT_SetError(SEC_ERROR_CERT_NO_RESPONSE);
        p11_kit_uri_free(URI);
        return (CERTCertificate *)NULL;
    }

    list = CERT_CreateSubjectCertList(NULL, handle, name, 0, PR_FALSE);
    if (list == NULL) {
        p11_kit_uri_free(URI);
        return (CERTCertificate *)NULL;
    }
    
    node = head = CERT_LIST_HEAD(list);
    if (head) {
        do {
            
            if (node->cert && SECITEM_ItemsAreEqual(&node->cert->subjectKeyID, id->pValue) &&
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
    p11_kit_uri_free(URI);
    return cert;
}

/*
SECKEYPRivateKey *
PK11_FindPrivateKeyByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
    P11KitUri *URI;
    //SECItem *keyID = NULL;
    CK_ATTRIBUTE *keyinfo = NULL;
    SECKEYPRivateKey *resultKey = NULL;
    int uristatus;

    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT, URI);
    if (p11ToNSSError(uristatus) != 0) {
        PORT_SetError(p11ToNSSError(uristatus))
        return NULL;
    }
    keyinfo = p11_kit_uri_get_attribute(URI, CKA_ID);
    if (!keyinfo) {
        return NULL;
    }
    //ask about this
    resultKey = PK11_FindKeyByKeyID(slot, (SECItem *)keyinfo->pValue, wincx);
    if (!resultKey)
        return NULL;
    return resultKey;
} 
*/