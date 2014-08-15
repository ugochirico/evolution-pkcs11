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

#include "util.h"

CK_RV set_attribute_template (CK_ATTRIBUTE_PTR att, CK_VOID_PTR value, CK_ULONG value_len)
{
	CK_RV rv = CKR_OK;
	if (att->pValue != NULL){
		if (att->ulValueLen >= value_len){
			if (value != NULL) {
				memcpy (att->pValue, value, value_len);
			} else {
				att->pValue = NULL;
			}
		}else{
			rv = CKR_BUFFER_TOO_SMALL;
		}
	}
	att->ulValueLen = value_len;
	return rv;
}

