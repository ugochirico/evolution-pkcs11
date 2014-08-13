#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"

void test_attribute_value (CK_FUNCTION_LIST_PTR pkcs11, 
		CK_SLOT_ID slotID, 
		CK_SESSION_HANDLE session_handle, 
		CK_OBJECT_HANDLE object_handle)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE  attribute_list[16];
	CK_ULONG attribute_list_size = 16, i;

	attribute_list[0].type = CKA_VALUE;
	attribute_list[0].pValue = NULL;
	attribute_list[0].ulValueLen = 0;

	attribute_list[1].type = CKA_ISSUER;
	attribute_list[1].pValue = NULL;
	attribute_list[1].ulValueLen = 0;

	rv = pkcs11->C_GetAttributeValue (session_handle, object_handle, attribute_list, attribute_list_size);
	g_assert (rv == CKR_OK);

	attribute_list[0].pValue = malloc(attribute_list[0].ulValueLen);
	attribute_list[1].pValue = malloc(attribute_list[1].ulValueLen);

	rv = pkcs11->C_GetAttributeValue (session_handle, object_handle, attribute_list, attribute_list_size);
	g_assert (rv == CKR_OK);

	printf ("Value Size: %lu\n", attribute_list[0].ulValueLen);
	printf ("Certificate: ");
	for (i = 0; i < attribute_list[0].ulValueLen; i++) {
		printf ("%02X:", ((CK_BYTE_PTR)attribute_list[0].pValue)[i] );
	}
	printf ("Issuer Size: %lu\n", attribute_list[1].ulValueLen);
	for (i = 0; i < attribute_list[1].ulValueLen; i++) {
		printf ("%02X:", ((CK_BYTE_PTR)attribute_list[1].pValue)[i] );
	}

	free(attribute_list[0].pValue);
	free(attribute_list[1].pValue);

}
