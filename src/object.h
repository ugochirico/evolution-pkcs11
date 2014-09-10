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

#ifndef __EVO_PKCS11_OBJECT_H__
#define __EVO_PKCS11_OBJECT_H__

#include <nss3/cert.h>
#include <libebook/libebook.h>
#include <glib.h>

#define EVOLUTION_PKCS11_TRUST_MASK		0x80000000

typedef struct Object {
	CK_ULONG handle;
	SECItem *derCert;
	CERTCertificate *certificate;
	char *label;

	/* trust related */
	CK_ULONG trust_handle;
	CK_BYTE sha1[20];
	CK_BYTE md5[16];

} Object;

Object *new_object (EContact *contact, CK_ULONG handle);

gboolean compare_object_issuer (Object *obj, SECItem *issuerName) ;
gboolean compare_object_serial (Object *obj, SECItem *serial_number) ;
gint object_compare_func (gconstpointer a, gconstpointer b);

void destroy_object (gpointer data);

#endif /* __EVO_PKCS11_OBJECT_H__ */
