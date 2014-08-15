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

void test_search (
		CK_FUNCTION_LIST_PTR pkcs11, 
		CK_SLOT_ID slotID, 
		CK_SESSION_HANDLE session_handle, 
		char *string_to_search, 
		unsigned int string_to_search_len, 
		CK_OBJECT_HANDLE_PTR object_list, 
		CK_ULONG object_list_size, 
		CK_ULONG_PTR objects_found) 
{
	CK_RV rv = CKR_OK;

	CK_ATTRIBUTE  attribute_list[16];
	CK_ULONG attribute_list_size = 16;

	attribute_list_size = 3;
	attribute_list[0].type = CKA_CLASS;
	attribute_list[0].pValue = malloc (sizeof (CK_ULONG));
	*((CK_ULONG_PTR )attribute_list[0].pValue) = (CK_ULONG) CKO_CERTIFICATE;
	attribute_list[0].ulValueLen = sizeof (CKA_CLASS);

	attribute_list[1].type = CKA_TOKEN;
	attribute_list[1].pValue = malloc (sizeof (CK_BBOOL));
	*((CK_BBOOL *)attribute_list[1].pValue) = CK_TRUE;
	attribute_list[1].ulValueLen = sizeof (CK_BBOOL);

	attribute_list[2].type = CKA_LABEL;
	attribute_list[2].pValue = malloc (string_to_search_len+1);
	memcpy( (CK_BYTE_PTR)attribute_list[2].pValue, string_to_search, string_to_search_len);
	((CK_BYTE_PTR)attribute_list[2].pValue)[string_to_search_len] = '\0';
	attribute_list[2].ulValueLen = string_to_search_len;


	rv = pkcs11->C_FindObjectsInit (session_handle, attribute_list, attribute_list_size);
	g_assert (rv == CKR_OK);

	free (attribute_list[0].pValue);
	free (attribute_list[1].pValue);
	free (attribute_list[2].pValue);

	rv = pkcs11->C_FindObjects (session_handle, object_list, object_list_size, objects_found);
	g_assert (rv == CKR_OK);

	printf ("Objects found: %lu\n", *objects_found);

	rv = pkcs11->C_FindObjectsFinal (session_handle);
	g_assert (rv == CKR_OK);

	// g_assert (*objects_found != 0);
}
