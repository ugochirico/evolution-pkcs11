/*
 * evolution-pkcs11
 *
 * Copyright (C) 2014  Yuuma Sato
 *
 * evolution-pkcs11 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * evolution-pkcs11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with evolution-pkcs11.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

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
	CK_ULONG attribute_list_size = 2, i;

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
	printf ("\n");

	printf ("Issuer Size: %lu\n", attribute_list[1].ulValueLen);
	for (i = 0; i < attribute_list[1].ulValueLen; i++) {
		printf ("%02X:", ((CK_BYTE_PTR)attribute_list[1].pValue)[i] );
	}
	printf ("\n");

	free(attribute_list[0].pValue);
	free(attribute_list[1].pValue);

}
