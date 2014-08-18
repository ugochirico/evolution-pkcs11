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

#ifndef __EVO_PKCS11_SESSION_H__
#define __EVO_PKCS11_SESSION_H__

#include "object.h"
#include <libebook/libebook.h>

typedef struct Session {
	CK_SESSION_HANDLE handle;

	/* Used during object searches */
	GSList *cursor_list, *current_cursor;
	gboolean search_on_going;
	gboolean att_issuer;
	SECItem search_issuer;

	/* Objects that the session knows */
	GSList *objects_found;

	/* Trust related */
	gboolean att_trust;
	SECItem serial_number;
	GSList *trust_objects_found;
} Session;

void session_init_all_sessions ();
void session_init_session (Session *session);
gboolean session_is_session_valid (CK_SESSION_HANDLE hSession);
Session *session_open_session ();
Session *session_get_session (CK_SESSION_HANDLE hSession);
void session_close_session (CK_SESSION_HANDLE hSession);
void session_close_all_sessions (CK_SLOT_ID slotID);

gboolean session_object_exists (Session *session, EContact *contact, Object **object);

#endif /* __EVO_PKCS11_SESSION_H__ */
