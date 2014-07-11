#include <nss3/certt.h>
#include <libebook/libebook.h>
#include <glib.h>

typedef struct Object {
	CK_ULONG handle;
	CERTCertificate *cert;
} Object;

Object *new_object (EContact *contact, CK_ULONG handle);

gint object_compare_func (gconstpointer a, gconstpointer b);

void destroy_object (gpointer data);
