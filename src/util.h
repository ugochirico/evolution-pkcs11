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

#ifndef __EVO_PKCS11_UTIL_H__
#define __EVO_PKCS11_UTIL_H__

#include <nss3/cert.h>
#include <nss3/pkcs11n.h>

CK_RV set_attribute_template (CK_ATTRIBUTE_PTR att, CK_VOID_PTR value, CK_ULONG value_len);

#endif /* __EVO_PKCS11_UTIL_H__ */
