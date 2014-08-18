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

#include <glib.h>
#include "pkcs11.h"

void test_session (CK_FUNCTION_LIST_PTR pkcs11, CK_SLOT_ID slotID)
{
	CK_SESSION_HANDLE session_list[16];
	CK_SESSION_HANDLE session;
	CK_FLAGS flags = CKF_SERIAL_SESSION;
	CK_ULONG i;
	CK_RV rv;

	rv = pkcs11->C_CloseSession (18);
	g_assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session_list[0]);
	g_assert (rv == CKR_OK);
	rv = pkcs11->C_CloseSession (session_list[0]);
	g_assert (rv == CKR_OK);

	rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session_list[0]);
	g_assert (rv == CKR_OK);
	rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session_list[1]);
	g_assert (rv == CKR_OK);
	rv = pkcs11->C_CloseSession (session_list[1]);
	g_assert (rv == CKR_OK);
	rv = pkcs11->C_CloseSession (session_list[0]);
	g_assert (rv == CKR_OK);

	for (i = 0; i < 16; i++) {
		rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session_list[i]);
		g_assert (rv == CKR_OK);
	}

	rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session);
	g_assert (rv == CKR_SESSION_COUNT);

	for (i = 0; i < 16; i++) {
		rv = pkcs11->C_CloseSession (session_list[i]);
		g_assert (rv == CKR_OK);
	}

	rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session);
	g_assert (rv == CKR_OK);

	rv = pkcs11->C_CloseSession (session);
	g_assert (rv == CKR_OK);

	for (i = 0; i < 16; i++) {
		rv = pkcs11->C_OpenSession (slotID, flags, NULL, NULL, &session_list[i]);
		g_assert (rv == CKR_OK);
	}

	rv = pkcs11->C_CloseAllSessions (slotID);
	g_assert (rv == CKR_OK);
}
