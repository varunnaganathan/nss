//Similar to SECMOD_FindModule
SECMODModule *SECMOD_FindModuleByUri(char *uri)
{
    P11KitUri *URI = NULL;
    CK_INFO *moduleinfo = NULL;
    SECMODModuleList *listnode;
    SECMODModule *module = NULL;
    SECStatus status;
    int st;

    st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_MODULE, URI);
    if (st != P11_KIT_URI_OK)
    {
        //Raise error
    }
    /*
    * Ask what this means.Copied because was present in SECMOD_FindModule
    */
    if (!moduleLock) {
        PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
        return module;
    }
    SECMOD_GetReadLock(moduleLock);
    for(listnode =  modules; listnode != NULL; listnode = listnode->next)
    {
        status = PK11_GetModInfo(listnode->module, moduleinfo);
        if (status != SECSuccess) {
            return NULL;
        }
        /*
        * Match the module info to the URI
        */
        if (p11_kit_uri_match_module_info(URI, moduleinfo) == 1) {
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
    P11KitUri *URI = NULL;
    int st;
    PK11SlotInfo *slotinfo;
    SECStatus status;
    CK_TOKEN_INFO tokeninfo;
    NSSToken *tok = NULL;

    st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_TOKEN, URI);
    if(st != P11_KIT_URI_OK) {
        //Raise error
    }
    NSSRWLock_LockRead(td->tokensLock);
    for (tok  = (NSSToken *)nssListIterator_Start(td->tokens);
         tok != (NSSToken *)NULL;
         tok  = (NSSToken *)nssListIterator_Next(td->tokens))
    {
        if (nssToken_IsPresent(tok)) {
            slotinfo = tok->pk11slot;
            status = PK11_GetTokenInfo(slotinfo, &tokeninfo);
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

    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT, URI);
    if (uristatus != P11_KIT_URI_OK) {
        return (CERTCertificate *)NULL;
    }

    id = p11_kit_uri_get_attribute(URI,CKA_ID);
    object = p11_kit_uri_get_attribute(URI,CKA_LABEL);
    type = p11_kit_uri_get_attribute(URI,CKA_CLASS);

    if( !id || !object || !type) {
        return (CERTCertificate *)NULL;
    }

    list = CERT_CreateSubjectCertList(NULL, handle, name, 0, PR_FALSE);
    if (list == NULL)
        return (CERTCertificate *)NULL;
    
    node = head = CERT_LIST_HEAD(list);
    if (head) {
        do {
            if (node->cert && SECITEM_ItemsAreEqual(&node->cert->subjectKeyID, id->pValue) &&
                SECITEM_ItemsAreEqual(&node->cert->nickname, object->pValue)) {
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
    return cert;
}

SECKEYPRivateKey *
PK11_FindPrivateKeyByURI(PK11SlotInfo *slot, void *wincx, char *uri) {
    P11KitUri *URI;
    //SECItem *keyID = NULL;
    CK_ATTRIBUTE *keyinfo = NULL;
    SECKEYPRivateKey *resultKey = NULL;
    int uristatus;

    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT, URI);
    if (uristatus != P11_KIT_URI_OK) {
        return NULL;
    }
    keyinfo = p11_kit_uri_get_attribute(URI, CKA_ID);
    //ask about this
    resultKey = PK11_FindKeyByKeyID(slot, (SECItem *)keyinfo->pValue, wincx);
    if (!resultKey)
        return NULL;
    return resultKey;
} 