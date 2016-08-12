#include "pkcs11t.h"
#include "pk11func.h"
#include "secerr.h"
#include "prerror.h"

#include "p11uri.h"

int P11_Kit_To_NSS_Error(CK_RV rv) {
	switch(rv) {
		case P11URI_UNEXPECTED: {
			return SEC_ERROR_PKCS11_FUNCTION_FAILED;
			break;
		}
		case P11URI_BAD_SCHEME: {
			return SEC_ERROR_BAD_DATA;
			break;
		}
		case P11URI_BAD_ENCODING: {
			return SEC_ERROR_BAD_DATA;
			break;
		}
		case P11URI_BAD_SYNTAX: {
			return SEC_ERROR_BAD_DATA;
			break;
		}
		case P11URI_BAD_VERSION: {
			return SEC_ERROR_INVALID_ARGS;
			break;
		}
		/* Find better alternative */
		case P11URI_NOT_FOUND: {
			return SEC_ERROR_PKCS11_FUNCTION_FAILED;
			break;
		}
		default: {
			return SEC_ERROR_BAD_DATA;
		}

	}
}
