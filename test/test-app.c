#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dlfcn.h"
#include "pkcs11.h"

extern void test_session (CK_FUNCTION_LIST_PTR pkcs11, CK_SLOT_ID slotID);

extern void test_search (
		CK_FUNCTION_LIST_PTR pkcs11,
		CK_SLOT_ID slotID,
		CK_SESSION_HANDLE session_handle,
		char *string_to_search,
		unsigned int string_to_search_len,
		CK_OBJECT_HANDLE_PTR object_list,
		CK_ULONG object_list_size,
		CK_ULONG_PTR objects_found);
extern void test_attribute_value (CK_FUNCTION_LIST_PTR pkcs11,
		CK_SLOT_ID slotID,
		CK_SESSION_HANDLE session_handle,
		CK_OBJECT_HANDLE object_handle);

void print_info (CK_UTF8CHAR_PTR info, CK_ULONG size)
{
	gchar *string;

	string = calloc (size, 1);
	memcpy (string, info, size);

	printf ("%s\n", string);

	free (string);
}

int main (int argc, char **argv) 
{
	CK_RV rv = CKR_OK;
	CK_FUNCTION_LIST_PTR pkcs11;
	CK_RV (*C_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR) = 0;
	char *lib_path, *string_to_search;
	unsigned int string_to_search_len;

	CK_INFO info;
	CK_SLOT_INFO slot_info;
	CK_ULONG slot_list_size = 8;
	CK_SLOT_ID slot_list[slot_list_size];

	CK_TOKEN_INFO token_info;

	CK_ULONG i;
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE object_list[16];
	CK_ULONG object_list_size = 16, objects_found;
	
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

	rv = C_GetFunctionList (&pkcs11);
	g_assert (rv == CKR_OK);

	/**/
	rv = pkcs11->C_Initialize (NULL);
	g_assert (rv == CKR_OK);
	
	rv = pkcs11->C_GetInfo (&info);
	g_assert (rv == CKR_OK);

	printf ("CK_INFO\n");
	printf ("PKCS#11 version: %u.%u\n", 
			info.cryptokiVersion.major,
			info.cryptokiVersion.minor);
	printf ("Manufacturer ID: %s\n", info.manufacturerID);
	printf ("Flags: %lx\n", (CK_ULONG) info.flags);
	printf ("Library Description: ");
	print_info (info.libraryDescription, 32);
	printf ("library version: %u.%u\n",
			info.libraryVersion.major,
			info.libraryVersion.minor);

	rv = pkcs11->C_GetSlotList (CK_TRUE, slot_list, &slot_list_size);
	g_assert (rv == CKR_OK);

	printf ("Number of slots: %lu\n", slot_list_size);
	printf ("Slot number: ");
	for (i = 0; i < slot_list_size; i++) {
		printf ("%lu ", (CK_ULONG) slot_list[i]);
	}
	printf ("\n");

	/**/
	rv = pkcs11->C_GetSlotInfo (slot_list[0], &slot_info);
	g_assert (rv == CKR_OK);

	printf ("CK_SLOT_INFO\n");
	printf ("Slot description: ");
	print_info (slot_info.slotDescription, 64);
	printf ("Manufacturer ID: ");
	print_info (slot_info.manufacturerID, 32);
	printf ("Flags: %lx\n", slot_info.flags);
	printf ("Hardware version: %u.%u\n",
			slot_info.hardwareVersion.major,
			slot_info.hardwareVersion.minor);
	printf ("Firmware version: %u.%u\n",
			slot_info.firmwareVersion.major,
			slot_info.firmwareVersion.minor);

	rv = pkcs11->C_GetTokenInfo (slot_list[0], &token_info);
	g_assert (rv == CKR_OK);

	test_session (pkcs11, slot_list[0]);

	rv = pkcs11->C_OpenSession (slot_list[0], CKF_SERIAL_SESSION, NULL, NULL, &session_handle);
	g_assert (rv == CKR_OK);

	test_search (pkcs11,
			slot_list[0],
			session_handle,
			string_to_search,
			string_to_search_len,
			object_list,
			object_list_size,
			&objects_found);

	test_attribute_value (pkcs11,
			slot_list[0],
			session_handle,
			object_list[0]);

	rv = pkcs11->C_CloseSession(session_handle);
	g_assert (rv == CKR_OK);

	rv = pkcs11->C_Finalize (NULL);
	g_assert (rv == CKR_OK);

	rv = dlclose(pkcs11_so);
	if (rv != 0) {
		fprintf (stderr, "Could not dlclose\n");
	}

	return 0;
}

