#include "pkcs11t.h"
#include "pk11func.h"
#include "secerr.h"
#include "prerror.h"

#define PKCS11_H 1
#include <p11-kit/uri.h>

int p11ToNSSError(CK_RV rv) {
	switch(rv) {
		case P11_KIT_URI_OK: {
			return 0;
			break;
		}
		case P11_KIT_URI_UNEXPECTED: {
			return SEC_ERROR_PKCS11_FUNCTION_FAILED;
			break;
		}
		case P11_KIT_URI_BAD_SCHEME: {
			return SEC_ERROR_BAD_DATA;
			break;
		}
		case P11_KIT_URI_BAD_ENCODING: {
			return SEC_ERROR_BAD_DATA;
			break;
		}
		case P11_KIT_URI_BAD_SYNTAX: {
			return SEC_ERROR_BAD_DATA;
			break;
		}
		case P11_KIT_URI_BAD_VERSION: {
			return SEC_ERROR_INVALID_ARGS;
			break;
		}
		/* Find better alternative */
		case P11_KIT_URI_NOT_FOUND: {
			return SEC_ERROR_PKCS11_FUNCTION_FAILED;
			break;
		}

	}
}