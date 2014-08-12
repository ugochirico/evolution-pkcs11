#include <nss3/certt.h>
#include <glib.h>
#include <libebook/libebook.h>
#include "object.h"

typedef struct Session {
	CK_SESSION_HANDLE handle;

	/* Used during object searches */
	GSList *cursor_list, *current_cursor;
	gboolean search_on_going;
	gboolean att_issuer;
	SECItem search_issuer;

	/* Objects that the session knows */
	GSList *objects_found;

	/* References */
	gint ref;
} Session;

gboolean session_object_exists (Session *session, EContact *contact, Object **object);
