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

#include "object.h"
#include "util.h"

Object *get_or_create_object (GHashTable *objects_sha1, EContact *contact, CK_ULONG handle, gboolean *is_object_new)
{
	Object *obj;
	EContactCert *cert;
	SECItem *derCert;
	SECStatus rv;
	PRArenaPool *arena = NULL;
	CK_ULONG digest_size = 20;
	CK_BYTE sha1 [digest_size];

	cert = e_contact_get (contact, E_CONTACT_X509_CERT);
	if (cert == NULL) {
		g_warning ("evolution-pkcs11: Could not get contact's certificate.\n");
		return NULL;
	}

	util_checksum ((CK_BYTE_PTR) cert->data, cert->length, sha1, &digest_size, G_CHECKSUM_SHA1);
	obj = (Object *) g_hash_table_lookup (objects_sha1, &sha1);
	if (obj != NULL) {
		*is_object_new = FALSE;
		return obj;
	}

	obj = malloc (sizeof (Object));
	obj->handle = handle;
	obj->label = e_contact_get(contact, E_CONTACT_EMAIL_1);

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	obj->certificate = PORT_ArenaZAlloc (arena, sizeof(CERTCertificate));
	obj->certificate->arena = arena;

	derCert = malloc (sizeof (SECItem));
	derCert->type = siDERCertBuffer;
	derCert->data = malloc (cert->length);
	if (derCert->data == NULL) { 
		e_contact_cert_free (cert);
		SECITEM_FreeItem (derCert, PR_TRUE);
		free (obj);
		return NULL;
	}
	memcpy (derCert->data, cert->data, cert->length);
	derCert->len = cert->length;

	e_contact_cert_free (cert);

	obj->derCert = derCert;
	obj->certificate->derCert = *obj->derCert;

	rv = SEC_QuickDERDecodeItem(arena, obj->certificate, SEC_SignedCertificateTemplate, &obj->certificate->derCert);
	if (rv != SECSuccess )
	{
		g_warning ("evolution-pkcs11: Could not Decode Certificate.");

		SECITEM_FreeItem (derCert, PR_TRUE);
		free (obj);
		return NULL;
	}

	/* trust related */
	obj->trust_handle = handle | EVOLUTION_PKCS11_TRUST_MASK;
	memcpy (obj->sha1, sha1, digest_size);
	// digest_size = 20;
	// util_checksum (derCert->data, derCert->len, obj->sha1, &digest_size, G_CHECKSUM_SHA1);

	digest_size = 16;
	util_checksum (derCert->data, derCert->len, obj->md5, &digest_size, G_CHECKSUM_MD5);

	*is_object_new = TRUE;
	return obj;
}

gboolean compare_object_issuer (Object *obj, SECItem *issuer_name)
{
	SECItem tempder;
	gboolean rv = TRUE;

	tempder = obj->certificate->derIssuer;	

	if (!memcmp (tempder.data, issuer_name->data, MIN(issuer_name->len, tempder.len)))
		rv = FALSE;

	return rv;
}

gboolean compare_object_serial (Object *obj, SECItem *serial_number)
{
	SECItem tempder;
	gboolean rv = TRUE;

	tempder = obj->certificate->serialNumber;

	if (!memcmp (tempder.data, serial_number->data, MIN(serial_number->len, tempder.len)))
		rv = FALSE;

	return rv;
}

gint object_compare_func (gconstpointer a, gconstpointer b) 
{
	Object *obj;
	CK_ULONG *_a, *_b;

	obj = (Object *) a;
	_b = (CK_ULONG_PTR) b;

	if (*_b == obj->handle)
		return 0;
	else if (*_b == obj->trust_handle)
		return 0;
	return 1;
}

void destroy_object (gpointer data) 
{
	Object *obj = (Object *) data;

	SECITEM_FreeItem (obj->derCert, PR_TRUE);
	CERT_DestroyCertificate (obj->certificate);
	free (obj->label);
	free (obj);
}
