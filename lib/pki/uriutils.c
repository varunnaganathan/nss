//Similar to SECMOD_FindModule
SECMODModule *PK11_FindModuleByUri(char *uri)
{
	P11KitUri *URI = NULL;
	CK_ATTRIBUTE_POINTER library_descripton;
	CK_ATTRIBUTE_POINTER library_manufacturer;
	CK_ATTRIBUTE_POINTER library_version;
	SECMODModuleList *listnode;
	SECMODModule *module = NULL;
	CK_INFO *moduleinfo;
	SECStatus status;
	int st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_MODULE, URI);
	if (!st)
	{
		//Raise error
	}
	/*Have doubts regarding the CK_ATTRIBUTE_TYPE.passing ints 0 for library-description
	1 for libarry-manufacturer and 2 for library-version */
	library_description = p11_kit_uri_get_attribute(URI, 0);
	library_manufacturer = p11_kit_uri_get_attribute(URI, 1);
	library_version = p11_kit_uri_get_attribute(URI, 2);
	//Ask what this means.Copied because was present in SECMOD_FindModule
	if (!moduleLock) {
    	PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
		return module;
    }
    SECMOD_GetReadLock(moduleLock);
    for(listnode =  modules; listnode != NULL; listnode = listnode->next)
    {
    	status = PK11_GetModInfo(&listnode->module, moduleinfo);
    	//use PORT_Strcmp to compare
    	if(moduleinfo->manufacturerID == library_manufacturer && moduleinfo->libraryDescription == libraryDescription && moduleinfo->libraryVersion == libraryVersion)
    	{
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