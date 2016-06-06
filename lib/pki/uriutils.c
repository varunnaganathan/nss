//Similar to SECMOD_FindModule
SECMODModule *SECMOD_FindModuleByUri(char *uri)
{
	P11KitUri *URI = NULL;
	CK_ATTRIBUTE_POINTER library_descripton;
	CK_ATTRIBUTE_POINTER library_manufacturer;
	CK_ATTRIBUTE_POINTER library_version;
	SECMODModuleList *listnode;
	SECMODModule *module = NULL;
	CK_INFO *moduleinfo;
	SECStatus status;
    int st;

	st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_MODULE, URI);
	if (st == P11_KIT_URI_OK)
	{
		//Raise error
	}
	/*
    * Have doubts regarding the CK_ATTRIBUTE_TYPE.passing ints 0 for library-description
	* 1 for libarry-manufacturer and 2 for library-version 
    */
	library_description = p11_kit_uri_get_attribute(URI, 0);
	library_manufacturer = p11_kit_uri_get_attribute(URI, 1);
	library_version = p11_kit_uri_get_attribute(URI, 2);
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
    	status = PK11_GetModInfo(&listnode->module, moduleinfo);
    	/*
        * Match the module info to the URI
        */
        if (p11_kit_match_module_info(URI, moduleinfo) == 1) {
            module = &listnode->module;
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
    PRStatus nsserv;
    NSSToken *token;
    PK11SlotInfo *slotinfo;
    SECStatus status;
    CK_TOKEN_INFO tokeninfo;

    st = p11_kit_uri_format(uri, P11_KIT_URI_FOR_TOKEN, URI);
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
            if (p11_kit_uri_match_token_info(URI, &token_info) == 1)
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
    
    P11KitUri URI;
    int uristatus;
    CERTCertList *list;
    CERTCertificate *cert = NULL;
    CERTCertListNode *node, *head;
    CK_ATTRIBUTE_PTR id;
    CK_ATTRIBUTE_PTR object;
    CK_ATTRIBUTE_PTR type;

    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT, &URI);
    if (uristatus != P11_KIT_URI_OK) {
        return (CERTCertificate *)NULL;
    }

    id = p11_kit_uri_get_attribute(&URI,CKA_ID);
    object = p11_kit_uri_get_attribute(&URI,CKA_LABEL);
    type = p11_kit_uri_get_attribute(&URI,CKA_CLASS);

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
    P11KitUri URI;
    SECItem *keyID = NULL;
    SECKEYPRivateKey resultKey;

    uristatus = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_OBJECT, &URI);
    if (uristatus != P11_KIT_URI_OK) {
        return SECFailure;
    }
    keyID = p11_kit_uri_get_attribute(&URI, CKA_ID);
    resultKey = PK11_FindKeyByKeyID(slot, keyID, wincx);
    if (!resultKey)
        return NULL;
    return resultKey;
}