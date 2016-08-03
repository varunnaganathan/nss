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

CK_OBJECT_HANDLE *CERT_FindCertByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
    P11KitUri *URI;
    //CK_ATTRIBUTE attrs[3];
    int uristatus, objcount;
    //CK_ATTRIBUTE_PTR Id, Object;
    CK_ATTRIBUTE_PTR attributes;
    CK_ULONG numattrs, i;
    //CK_OBJECT_CLASS certclass = CKO_CERTIFICATE;
    CK_ATTRIBUTE *theTemplate;
    //{ CKA_ID, NULL, 0 },
    //{ CKA_LABEL, NULL, 0 },
    //{ CKA_CLASS, NULL, 0 },
    //};
    //int tsize = sizeof(theTemplate)/sizeof(theTemplate[0]);
    //CK_ATTRIBUTE *attr = theTemplate;
    CK_OBJECT_HANDLE *peerID;

    URI = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = p11_kit_uri_get_attributes(URI,&numattrs);
    theTemplate = malloc(sizeof(CK_ATTRIBUTE)*numattrs);
    for (i=0; i<numattrs; i++) {
        CK_ATTRIBUTE temp =  {attributes[i].type, attributes[i].pValue, attributes[i].ulValueLen};
        theTemplate[i] = temp;
    }
    //int tsize = sizeof(theTemplate)/sizeof(theTemplate[0]);

    //Id = p11_kit_uri_get_attribute(URI, CKA_ID);
    //Object = p11_kit_uri_get_attribute(URI, CKA_LABEL);
    //Type = p11_kit_uri_get_attribute(URI, CKA_CLASS);

    //PK11_SETATTRS(attr,CKA_ID, Id->pValue, Id->ulValueLen);attr++;
    //PK11_SETATTRS(attr,CKA_LABEL,Object->pValue,Object->ulValueLen);attr++;
    //PK11_SETATTRS(attr,CKA_CLASS,&certclass,sizeof(certclass));

    peerID = pk11_FindObjectsByTemplate(slot, theTemplate, numattrs, &objcount);
    free(theTemplate);
    return peerID;

}

CK_OBJECT_HANDLE *
PK11_FindPrivateKeyByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
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

    URI = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = p11_kit_uri_get_attributes(URI,&numattrs);
    theTemplate = malloc(sizeof(CK_ATTRIBUTE)*numattrs);
    for (i=0; i<numattrs; i++) {
        CK_ATTRIBUTE temp =  {attributes[i].type, attributes[i].pValue, attributes[i].ulValueLen};
        theTemplate[i] = temp;
    }

    peerID = pk11_FindObjectsByTemplate(slot, theTemplate, numattrs, &objcount);
    free(theTemplate);
    return peerID;
}

CK_OBJECT_HANDLE *
PK11_FindPrivateKeyByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
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

    URI = p11_kit_uri_new();
    if (!uri) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return CK_INVALID_HANDLE;
    }
    
    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, URI);
    if (uristatus != P11_KIT_URI_OK) {
        PORT_SetError(P11_Kit_To_NSS_Error(uristatus));
        return CK_INVALID_HANDLE;
    }

    attributes = p11_kit_uri_get_attributes(URI,&numattrs);
    theTemplate = malloc(sizeof(CK_ATTRIBUTE)*numattrs);
    for (i=0; i<numattrs; i++) {
        CK_ATTRIBUTE temp =  {attributes[i].type, attributes[i].pValue, attributes[i].ulValueLen};
        theTemplate[i] = temp;
    }

    peerID = pk11_FindObjectsByTemplate(slot, theTemplate, numattrs, &objcount);
    free(theTemplate);
    return peerID;
}