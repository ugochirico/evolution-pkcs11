#include "object.h"
#include <nss3/cert.h>
#include <nss3/base64.h>
#include <nss3/secerr.h>
#include <nss3/secpkcs7.h>
#include <nss3/pk11pub.h>
#include <nss3/keyhi.h>

Object *new_object (EContact *contact, CK_ULONG handle) 
{
	Object *obj;
	EContactCert *cert;
	SECItem *derCert;
	SECStatus rv;
	PRArenaPool *arena = NULL;

	cert = e_contact_get (contact, E_CONTACT_X509_CERT);
	if (cert == NULL) {
		return NULL;
	}

	obj = malloc (sizeof (Object));
	obj->handle = handle;

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	obj->certificate = PORT_ArenaZAlloc (arena, sizeof(CERTCertificate));
	obj->certificate->arena = arena;

	derCert = malloc (sizeof (SECItem));
	derCert->type = siDERCertBuffer;
	derCert->data = malloc (cert->length);
	if (derCert->data == NULL) { 
		free (derCert);
		return NULL;
	}
	memcpy (derCert->data, cert->data, cert->length);
	derCert->len = cert->length;

	obj->derCert = derCert;
	obj->certificate->derCert = *obj->derCert;

	rv = SEC_QuickDERDecodeItem(arena, obj->certificate, SEC_SignedCertificateTemplate, &obj->certificate->derCert);
	if (rv != SECSuccess )
	{
		g_warning ("evolution-pkcs11: Could not Decode Certificate.");
		/* TODO Free obj */
		return NULL;
	}

	// SECKEYPublicKey *pubkey = NULL;
	// pubkey = SECKEY_ExtractPublicKey(&obj->certificate->subjectPublicKeyInfo.subjectPublicKey);
	// pubkey = SECKEY_DecodeDERPublicKey(&obj->certificate->subjectPublicKeyInfo.subjectPublicKey);
	// pubkey = SECKEY_ImportDERPublicKey(&obj->certificate->subjectPublicKeyInfo.subjectPublicKey, CKK_RSA);
	// if (pubkey == NULL) return NULL;

	return obj;
}

gboolean compare_object_issuer(Object *obj, SECItem *issuerName) 
{
	SECStatus sec_rv;
	SECItem tempder;
	gboolean rv = FALSE;

	// sec_rv = CERT_IssuerNameFromDERCert(obj->derCert, &tempder);
	tempder = obj->certificate->derIssuer;	
	// if (sec_rv != SECSuccess) return FALSE;

	if (!memcmp (tempder.data, issuerName->data, MIN(issuerName->len, tempder.len))) rv = TRUE;

	return rv;
}

gint object_compare_func (gconstpointer a, gconstpointer b) 
{
	CK_ULONG *_a, *_b;
	_a = (CK_ULONG_PTR) a;
	_b = (CK_ULONG_PTR) b;

	return (gint) *_a - *_b;
}

void destroy_object (gpointer data) 
{
	Object *obj = (Object *) data;

	free (obj->derCert);
	// free (obj);
}
