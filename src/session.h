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
} Session;

void session_init_all_sessions ();
void session_init_session (Session *session);
gboolean session_is_session_valid (CK_SESSION_HANDLE hSession);
Session *session_open_session ();
Session *session_get_session (CK_SESSION_HANDLE hSession);
void session_close_session (CK_SESSION_HANDLE hSession);
void session_close_all_sessions (CK_SLOT_ID slotID);

gboolean session_object_exists (Session *session, EContact *contact, Object **object);
