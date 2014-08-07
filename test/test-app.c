#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dlfcn.h"
#include "pkcs11.h"

int main (int argc, char **argv) 
{
	CK_RV rv = CKR_OK;
	CK_FUNCTION_LIST_PTR pkcs11;
	CK_RV (*C_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR) = 0;
	char *lib_path, *string_to_search;
	unsigned int string_to_search_len;

	CK_INFO info;
	CK_SLOT_INFO slot_info;
	CK_SLOT_ID slot_list[8];
	CK_ULONG ulong, i;
	CK_SESSION_HANDLE session_handle;
	CK_ATTRIBUTE  attribute_list[16];
	CK_ULONG attribute_list_size = 16;
	CK_OBJECT_HANDLE object_list[16];
	CK_ULONG object_list_size = 16, objects_found;
	
	CK_ATTRIBUTE  attribute_value_list[2];
	CK_ULONG attribute_value_list_size = 2;

	if (argc >= 2) 
		lib_path = argv[1];

	if (argc >= 3)
		string_to_search = argv[2];

	string_to_search_len = strlen(string_to_search);

	void *pkcs11_so;
	pkcs11_so = dlopen (lib_path, RTLD_NOW);
	if (pkcs11_so == NULL) {
		fprintf (stderr, "Could not load library: %s\n", dlerror());
		return CKR_GENERAL_ERROR;
	}

	C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(pkcs11_so, "C_GetFunctionList");
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not load C_GetFunctionList\n");
	}

	rv = C_GetFunctionList (&pkcs11);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not get function list\n");
	}

	/**/
	rv = pkcs11->C_Initialize (NULL);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_Initialize\n");
	}
	
	/**/
	rv = pkcs11->C_GetInfo (&info);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_GetInfo\n");
	}

	printf ("Info\n");
	printf ("PKCS#11 version: %u.%u\n", 
			info.cryptokiVersion.major,
			info.cryptokiVersion.minor);
	printf ("Manufacturer: %s\n", info.manufacturerID);

	/**/
	ulong = 8;
	rv = pkcs11->C_GetSlotList (CK_TRUE, slot_list, &ulong);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_GetSlotList\n");
	}

	printf ("Number of slots: %lu\n", ulong);
	printf ("Slot number: ");
	for (i = 0; i < ulong; i++) {
		printf ("%lu ", (CK_ULONG) slot_list[i]);
	}
	printf ("\n");

	/**/
	rv = pkcs11->C_GetSlotInfo (slot_list[0], &slot_info);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_GetSlotInfo\n");
	}

	/**/
	/**/

	rv = pkcs11->C_OpenSession (slot_list[0], CKF_SERIAL_SESSION, NULL, NULL, &session_handle);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_OpenSession\n");
	}

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
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_FindObjectsInit\n");
		return 0;
	}

	free (attribute_list[0].pValue);
	free (attribute_list[1].pValue);
	free (attribute_list[2].pValue);

	rv = pkcs11->C_FindObjects (session_handle, object_list, object_list_size, &objects_found);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_FindObjects\n");
		return 0;
	}

	printf ("Objects found: %lu\n", objects_found);

	rv = pkcs11->C_FindObjectsFinal (session_handle);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_FindObjectsFinal\n");
		return 0;
	}

	if (objects_found == 0) return 0;

	attribute_value_list[0].type = CKA_VALUE;
	attribute_value_list[0].pValue = NULL;
	attribute_value_list[0].ulValueLen = 0;

	attribute_value_list[1].type = CKA_ISSUER;
	attribute_value_list[1].pValue = NULL;
	attribute_value_list[1].ulValueLen = 0;

	rv = pkcs11->C_GetAttributeValue (session_handle, object_list[0], attribute_value_list, attribute_value_list_size);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_GetAttributeValue\n");
	}

	attribute_value_list[0].pValue = malloc(attribute_value_list[0].ulValueLen);
	attribute_value_list[1].pValue = malloc(attribute_value_list[1].ulValueLen);

	rv = pkcs11->C_GetAttributeValue (session_handle, object_list[0], attribute_value_list, attribute_value_list_size);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_GetAttributeValue\n");
	}

	printf ("Value Size: %lu\n", attribute_value_list[0].ulValueLen);
	printf ("Certificate: ");
	for (i = 0; i < attribute_value_list[0].ulValueLen; i++) {
		printf ("%02X:", ((CK_BYTE_PTR)attribute_value_list[0].pValue)[i] );
	}
	printf ("Issuer Size: %lu\n", attribute_value_list[1].ulValueLen);
	for (i = 0; i < attribute_value_list[1].ulValueLen; i++) {
		printf ("%02X:", ((CK_BYTE_PTR)attribute_value_list[1].pValue)[i] );
	}


	free(attribute_value_list[0].pValue);
	free(attribute_value_list[1].pValue);

	rv = pkcs11->C_CloseSession(session_handle);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_CloseSession\n");
	}

	rv = pkcs11->C_Finalize (NULL);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_Finalize\n");
	}

	rv = dlclose(pkcs11_so);
	if (rv != 0) {
		fprintf (stderr, "Could not dlclose\n");
	}

	return 0;
}

