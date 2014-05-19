#include <stdio.h>
#include <nss3/nss.h>
#include <nss3/secmod.h>
#include <nss3/cert.h>
#include <nss3/certt.h>

char *passwdcb (PK11SlotInfo *info, PRBool retry, void *arg)
{
	  if (!retry)
		      return PL_strdup ("");
	    else
			    return NULL;
}

int main (int argc, char **argv) 
{
	int rv;
	SECStatus s;
	CERTCertDBHandle *db_handle;
	CERTCertList *cert_list = NULL;
	CERTCertificate *cert = NULL;
	SECMODModule *internal_module = NULL;
	PK11SlotInfo *slot = NULL;
	CK_SLOT_INFO ck_slot_info;
	char token_name[] = "Token Addressbook               ";
	PRBool b;

	/* Initialize */
	PK11_SetPasswordFunc (passwdcb);
	s = NSS_InitReadWrite ("/home/yuuma/.pki/nssdb/");	
	if (s != SECSuccess) {
		rv = 1;
		goto _fail;
	}

	slot = PK11_FindSlotByName (token_name);
	if (slot == NULL){
		rv = 3;
		goto _fail;
	}

	s = PK11_GetSlotInfo (slot, &ck_slot_info);
	if (s != SECSuccess) {
		rv = 31;
		goto _fail;
	}

	printf ("Slot Description: [%s]\n", ck_slot_info.slotDescription);

	b = PK11_NeedLogin (slot);
	if (b) 
		printf ("Slot needs login\n");
	else
		printf ("Slot doesn't need login\n");

	b = PK11_IsLoggedIn (slot, NULL);
	if (b) 
		printf ("Slot logged in\n");
	else
		printf ("Slot not logged in\n");

	b = PK11_IsFriendly (slot);
	if (b) 
		printf ("Slot is friendly\n");
	else
		printf ("Slot unfriendly\n");

	cert_list = PK11_FindCertsFromEmailAddress ("satoyuuma@gmail.com", NULL);
	if (cert_list == NULL){
		rv = 4;
		goto _fail;
	}

_fail:
	printf ("RV: [%x]\n", rv);
	return rv;
}

