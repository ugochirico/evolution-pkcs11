/*
 * evolution-pkcs11
 *
 * Copyright (C) 2014  Yuuma Sato
 *
 * evolution-pkcs11 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * evolution-pkcs11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with evolution-pkcs11.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "session.h"
#include "util.h"
#include <string.h>

#define EVOLUTION_PKCS11_MAX_SESSION_NUMBER 16
#define EVOLUTION_PKCS11_SESSION_MASK		0x80000000


guint sha1_hash (gconstpointer key)
{
	gsize digest_len = 20;
	CK_BYTE_PTR sha1 = (CK_BYTE_PTR) key;
	CK_BYTE hash[digest_len];
	guint sha1_hash;

	util_checksum (sha1, 20, hash, &digest_len, G_CHECKSUM_SHA1);

	memcpy (&sha1_hash, hash, sizeof (sha1_hash));
	return sha1_hash;
}

gboolean sha1_equal (gconstpointer a, gconstpointer b)
{
	gboolean equal = TRUE;
	CK_BYTE_PTR hash_a, hash_b;

	hash_a = (CK_BYTE_PTR) a;
	hash_b = (CK_BYTE_PTR) b;

	if (memcmp (hash_a, hash_b, 20))
		equal = FALSE;

	return equal;
}

guint secitem_hash (gconstpointer key)
{
	gsize digest_len = 20;
	SECItem *secitem;
	CK_BYTE hash[digest_len];
	guint secitem_hash;

	secitem = (SECItem *) key;
	util_checksum (secitem->data, secitem->len, hash, &digest_len, G_CHECKSUM_SHA1);

	memcpy (&secitem_hash, hash, sizeof (secitem_hash));
	return secitem_hash;
}

gboolean secitem_equal (gconstpointer a, gconstpointer b)
{
	gboolean equal = TRUE;
	SECItem *secitem_a, *secitem_b;

	secitem_a = (SECItem *) a;
	secitem_b = (SECItem *) b;

	if (memcmp (secitem_a->data, secitem_b->data, MIN (secitem_a->len, secitem_b->len) ))
		equal = FALSE;
	return equal;
}

gboolean destroy_objects_issuer_list (gpointer key, gpointer value, gpointer user_data)
{
	GSList *list;

	list = (GSList *) value;
	g_slist_free (list);
	return TRUE;
}

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

	session->objects_handle = NULL;
	session->objects_sha1 = NULL;
	session->objects_issuer = NULL;

	session->att_trust = FALSE;
	session->serial_number.len = 0;
	session->serial_number.data = NULL;
	session->trust_objects_from_issuer = NULL;
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

			session->objects_handle = g_hash_table_new (g_int_hash, g_int_equal);
			session->objects_sha1 = g_hash_table_new_full (sha1_hash, sha1_equal, NULL, destroy_object);
			session->objects_issuer = g_hash_table_new (secitem_hash, secitem_equal);
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

	if (session->objects_handle)
		g_hash_table_destroy (session->objects_handle);

	if (session->objects_sha1)
		g_hash_table_destroy (session->objects_sha1);

	if (session->objects_issuer) {
		g_hash_table_foreach_remove (session->objects_issuer, destroy_objects_issuer_list, NULL);
		g_hash_table_destroy (session->objects_issuer);
	}

	session_init_session (session);
}

/* Check if the contact's certificate has already been delivered by
 * a previous search in the session */
gboolean session_object_exists (Session *session, EContact *contact, Object **object)
{
	EContactCert *cert = NULL;
	gboolean found = FALSE;
	CK_ULONG sha1_size = 20;
	CK_BYTE sha1[sha1_size];

	if (contact == NULL) return found;
	if (session == NULL) return found;

	cert = e_contact_get (contact, E_CONTACT_X509_CERT);
	if (cert == NULL) {
		return found;
	}

	util_checksum ((CK_BYTE_PTR) cert->data, cert->length, sha1, &sha1_size, G_CHECKSUM_SHA1);
	*object = (Object *) g_hash_table_lookup (session->objects_sha1, &sha1);
	if (*object != NULL)
		found = TRUE;

	e_contact_cert_free (cert);

	return found;
}
