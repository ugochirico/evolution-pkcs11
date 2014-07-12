#include "object.h"
#include <nss3/cert.h>
#include <nss3/base64.h>
#include <nss3/secerr.h>
#include <nss3/secpkcs7.h>

Object *new_object (EContact *contact, CK_ULONG handle) {
	Object *obj;
	EContactCert *cert;
	char *temp;
	SECItem *derCert;
	SECStatus rv;

	cert = e_contact_get (contact, E_CONTACT_X509_CERT);
	if (cert == NULL) {
		return NULL;
	}

	obj = malloc (sizeof (Object) );
	obj->handle = handle;

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

	return obj;
}

gint object_compare_func (gconstpointer a, gconstpointer b) {
	CK_ULONG *_a, *_b;
	_a = (CK_ULONG_PTR) a;
	_b = (CK_ULONG_PTR) b;

	return (gint) *_a - *_b;
}

void destroy_object (gpointer data) {
	Object *obj = (Object *) data;

	free (obj->derCert);
	// free (obj);
}
