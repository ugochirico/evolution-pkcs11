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

#include "pkcs11.h"
#include <stdio.h>
#include <prerror.h>
#include <nss3/nss.h>
#include <nss3/secmod.h>
#include <nss3/cert.h>
#include <nss3/certt.h>

void print_loaded_modules () {
	SECMODModuleList *list;

	list = SECMOD_GetDefaultModuleList ();

	printf ("Modules list\n");
	while (list != NULL) {
		if (list->module != NULL) {
			printf ("Module name: %s\n", list->module->commonName);
		}
		list = list->next;
	}
}

int main (int argc, char **argv) 
{
	CK_RV rv = CKR_OK;
	char *module_spec;
	SECMODModule *module;
	SECStatus status = SECSuccess;
	CK_FUNCTION_LIST_PTR pkcs11;

	print_loaded_modules();

	module_spec = "library=/home/yuuma/local/lib/evolution-pkcs11.so name=YUUMA_MODULE";
	module = SECMOD_LoadUserModule(module_spec, NULL, PR_FALSE);
	if (module == NULL || !module->loaded) {
		const PRErrorCode err = PR_GetError();
		fprintf(stderr, "error: NSPR error code %d: %s\n",
				err, PR_ErrorToName(err));
	}

	if (module->functionList == NULL) {
		fprintf (stderr, "FunctionList empty\n");
	}
	pkcs11 = module->functionList;

	rv = pkcs11->C_Finalize(NULL);
	if (rv != CKR_OK) {
		fprintf (stderr, "Could not C_Finalize\n");
	}

	print_loaded_modules();

	char character;
	scanf ("%c", &character);

	status = SECMOD_UnloadUserModule (module);
	if (status != SECSuccess)
		fprintf (stderr, "Error unloading module\n");

	print_loaded_modules();

	return rv;
}

