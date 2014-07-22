#include "util.h"

CK_RV set_attribute_template (CK_ATTRIBUTE_PTR att, CK_VOID_PTR value, CK_ULONG value_len)
{
	CK_RV rv = CKR_OK;
	if (att->pValue != NULL){
		if (att->ulValueLen >= value_len){
			if (value != NULL) {
				memcpy (att->pValue, value, value_len);
			} else {
				att->pValue = NULL;
			}
		}else{
			rv = CKR_BUFFER_TOO_SMALL;
		}
	}
	att->ulValueLen = value_len;
	return rv;
}

