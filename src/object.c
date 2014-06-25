#include "object.h"
#include <nss3/cert.h>
#include <nss3/base64.h>

Object *new_object (EContact *contact, CK_ULONG handle) {
	Object *obj;
	EContactCert *cert;
	char *temp;
	SECItem *der;
	SECStatus rv;

	cert = e_contact_get (contact, E_CONTACT_X509_CERT);
	if (cert == NULL) {
		return NULL;
	}

	obj = malloc (sizeof (Object) );
	obj->handle = handle;

	temp = malloc (cert->length +1);
	memcpy (temp, cert->data, cert->length);
	temp[cert->length] = '\0';

	der = malloc (sizeof (SECItem));

	rv = ATOB_ConvertAsciiToItem (der, temp);
	free (temp);
	if (rv != SECSuccess) {
		free (obj);
		return NULL;
	}
	obj->der = der;

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

	free (obj->der);
	// free (obj);
}
