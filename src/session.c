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

#include "session.h"
#include <string.h>

#define EVOLUTION_PKCS11_MAX_SESSION_NUMBER 16
#define EVOLUTION_PKCS11_SESSION_MASK		0x80000000

Session session_list[EVOLUTION_PKCS11_MAX_SESSION_NUMBER];

void session_init_all_sessions ()
{
	CK_ULONG i;
	for (i = 0; i < EVOLUTION_PKCS11_MAX_SESSION_NUMBER; i++) {
		session_init_session(&session_list[i]);
	}
}


void session_init_session (Session *session)
{
	session->handle = 0;

	session->cursor_list = NULL;
	session->current_cursor = NULL;
	session->search_on_going = FALSE;
	session->att_issuer = FALSE;
	session->search_issuer.len = 0;
	session->search_issuer.data = NULL;

	session->objects_found = NULL;
}

gboolean session_is_session_valid (CK_SESSION_HANDLE hSession)
{
	CK_ULONG i = ~EVOLUTION_PKCS11_SESSION_MASK & hSession;

	if (i < EVOLUTION_PKCS11_MAX_SESSION_NUMBER) {
		if (session_list[i].handle == hSession)
			return TRUE;
	}
	return FALSE;
}

Session *session_open_session ()
{
	Session *session = NULL;
	CK_ULONG i = 0;

	while (session == NULL && i < EVOLUTION_PKCS11_MAX_SESSION_NUMBER) {
		if (session_list[i].handle == 0){
			session = &session_list[i];
			session->handle = i | EVOLUTION_PKCS11_SESSION_MASK;
		}
		i++;
	}
	return session;
}

Session *session_get_session (CK_SESSION_HANDLE hSession)
{
	Session *session = NULL;
	CK_ULONG i = (!EVOLUTION_PKCS11_SESSION_MASK) & hSession;

	if (i < EVOLUTION_PKCS11_MAX_SESSION_NUMBER) {
		if (session_list[i].handle == hSession)
			session = &session_list[i];
	}
	return session;
}

void session_close_all_sessions (CK_SLOT_ID slotID)
{
	CK_ULONG i;
	for (i = 0; i < EVOLUTION_PKCS11_MAX_SESSION_NUMBER; i++) {
		session_close_session(session_list[i].handle);
	}
}

void session_close_session (CK_SESSION_HANDLE hSession)
{
	Session *session = NULL;
	CK_ULONG i = ~EVOLUTION_PKCS11_SESSION_MASK & hSession;

	session = &session_list[i];

	if (session->objects_found != NULL) {
		g_slist_free_full (session->objects_found, destroy_object);
		session->objects_found = NULL;
	}

	session_init_session (session);
}

/* Check if the contact's certificate was already delivered by
 * a previous search in the session */
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
