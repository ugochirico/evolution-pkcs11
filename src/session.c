#include "session.h"
#include <string.h>

gboolean session_object_exists (Session *session, EContact *contact, Object **object)
{
	EContactCert *cert = NULL;
	Object *obj;
	GSList *list;
	gboolean found = FALSE;

	if (contact == NULL) return FALSE;
	if (session == NULL) return FALSE;

	cert = e_contact_get (contact, E_CONTACT_X509_CERT);
	if (cert == NULL) {
		return found;
	}

	list = session->objects_found;
	while (list != NULL) {
		obj = (Object*) list->data;
		if (!memcmp (cert->data, obj->derCert->data, MIN (cert->length, obj->derCert->len))) {
			*object = obj;
			found = TRUE;
			break;
		}
		list = list->next;
	}

	e_contact_cert_free (cert);

	return found;
}
