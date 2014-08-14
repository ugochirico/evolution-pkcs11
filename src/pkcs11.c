#include "pkcs11.h"
#include "object.h"
#include "session.h"
#include "util.h"
#include <libebook/libebook.h>
#include <shell/e-shell.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern CK_FUNCTION_LIST pkcs11_function_list;

static CK_UTF8CHAR manufacturerID[] =		"Yuuma Sato                      ";
static CK_UTF8CHAR libraryDescription[] =	"CertModule PKCS#11 API          ";

static CK_OBJECT_HANDLE object_handle_counter;

/* Used to access evolution addressbook */
static ESourceRegistry *registry;

CK_RV C_Initialize (CK_VOID_PTR pInitArgs)
{
	GError *error = NULL;

	object_handle_counter = 1;

	registry = e_source_registry_new_sync (NULL, &error);
	if (registry == NULL) {
		g_warning ("evolution-pkcs11: Failed to get registry: %s\n", error->message);
		g_error_free (error);
		return CKR_FUNCTION_FAILED;
	}

	session_init_all_sessions ();
	
	return CKR_OK;
}

CK_RV C_Finalize (CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	
	g_object_unref (registry);
	
	return rv;
}

CK_RV C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_function_list;
	return CKR_OK;
}

CK_RV C_GetInfo (CK_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	memset (pInfo, 0, sizeof(CK_INFO));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 20;

	memcpy (pInfo->manufacturerID,
		  manufacturerID,
		  32);
	memcpy (pInfo->libraryDescription,
		  libraryDescription,
		  32);
	pInfo->libraryVersion.major = 0;
	pInfo->libraryVersion.minor = 0; 

	return rv;
}

CK_RV C_GetSlotList (CK_BBOOL tokenPresent,  
		    CK_SLOT_ID_PTR pSlotList, 
		    CK_ULONG_PTR   pulCount)   
{
	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pSlotList == NULL_PTR) {
		*pulCount = 1;
		return CKR_OK;
	}

	if (*pulCount < 1) {
		*pulCount = 1;
		return CKR_BUFFER_TOO_SMALL;
	}

	*pSlotList = (CK_ULONG) 14;
	*pulCount = 1;

	return CKR_OK;
}


CK_RV C_GetSlotInfo (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{

	CK_UTF8CHAR slotDescription[] = "Slot unico do modulo                                            "; 

	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	memset (pInfo, 0, sizeof (CK_SLOT_INFO));
	memcpy (pInfo->slotDescription, slotDescription, 64); 
	memcpy (pInfo->manufacturerID, manufacturerID, 32); 
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 1;

	return CKR_OK;
}

CK_RV C_GetTokenInfo (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	CK_UTF8CHAR label[] =	"Token Addressbook               ";
	CK_UTF8CHAR model[] =	"modelo virtual  ";
	CK_UTF8CHAR serial[] =	"0123456789ABCDEF";

	memset (pInfo, 0, sizeof (CK_TOKEN_INFO));
	memcpy (pInfo->label,label , 32); 
	memcpy (pInfo->manufacturerID, manufacturerID, 32); 
	memcpy (pInfo->model, model, 16); 
	memcpy (pInfo->serialNumber, serial, 16); 
	pInfo->flags = 0;
	pInfo->ulMaxSessionCount = 0;
	pInfo->ulSessionCount = 0;
	pInfo->ulMaxRwSessionCount = 0;
	pInfo->ulRwSessionCount = 0;
	pInfo->ulMaxPinLen = 8;
	pInfo->ulMinPinLen = 6;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;

	return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{

	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pMechanismList == NULL_PTR){
		*pulCount = 0;
		return CKR_OK;
	}

	*pulCount = 0;

	return CKR_OK;
}

CK_RV C_GetMechanismInfo (CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken (CK_SLOT_ID slotID,
		  CK_CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent (CK_FLAGS flags, 
			 CK_SLOT_ID_PTR pSlot, 
			 CK_VOID_PTR pReserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession (CK_SLOT_ID slotID,
		    CK_FLAGS flags,
		    CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{			
	Session *session = NULL;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION))
		return CKR_ARGUMENTS_BAD;

	session = session_open_session ();
	if (session == NULL) return CKR_SESSION_COUNT;

	*phSession =  session->handle;

	return CKR_OK;
}


CK_RV C_CloseSession (CK_SESSION_HANDLE hSession)
{
	if (!session_is_session_valid (hSession))
		return CKR_SESSION_HANDLE_INVALID;

	session_close_session (hSession);

	return CKR_OK;
}

CK_RV C_CloseAllSessions (CK_SLOT_ID slotID)
{			
	CK_RV rv = CKR_OK;

	session_close_all_sessions (slotID);

	return rv;
}

CK_RV C_GetSessionInfo (CK_SESSION_HANDLE hSession,
		       CK_SESSION_INFO_PTR pInfo)
{			
	if (!session_is_session_valid (hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = (CK_ULONG) 14;
	pInfo->state = CKS_RO_PUBLIC_SESSION;
	pInfo->flags = CKF_SERIAL_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}

CK_RV C_GetOperationState (CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{		
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState (CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login (CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_CHAR_PTR pPin,
	      CK_ULONG ulPinLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout (CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN (CK_SESSION_HANDLE hSession,
	       CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_CreateObject (CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,	
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_CopyObject (CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,	
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phNewObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DestroyObject (CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_GetObjectSize (CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject,	
		      CK_ULONG_PTR pulSize)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue (CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,	
		CK_ATTRIBUTE_PTR pTemplate,	
		CK_ULONG ulCount)		
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;
	CK_ATTRIBUTE_PTR current_attribute;
	GSList *object;
	SECItem *derCert;
	CERTCertificate *certificate;
	CK_VOID_PTR value;
	CK_ULONG value_len;
	Session *session = NULL;

	CK_BBOOL p11_boolean;
	CK_ULONG p11_ulong;

	if (!session_is_session_valid (hSession))
		return CKR_SESSION_HANDLE_INVALID;

	session = session_get_session (hSession);

	object = g_slist_find_custom (session->objects_found, &hObject, object_compare_func);
	
	if (object == NULL) return CKR_OBJECT_HANDLE_INVALID;

	derCert = ((Object *)object->data)->derCert;
	certificate = ((Object *)object->data)->certificate;

	for (i = 0; i < ulCount; i++){
		current_attribute = &pTemplate[i];
		switch (current_attribute->type){

			case (CKA_TOKEN):
				p11_boolean = CK_TRUE;
				value = &p11_boolean;
				value_len = sizeof (CK_BBOOL);
				break;

			case (CKA_VALUE):
				value = derCert->data;
				value_len = derCert->len;
				break;

			case (CKA_CERTIFICATE_TYPE):
				p11_ulong = CKC_X_509;
				value = &p11_ulong; 
				value_len = sizeof (CK_CERTIFICATE_TYPE);
				break;

			case (CKA_ISSUER):
				value = certificate->derIssuer.data;
				value_len = certificate->derIssuer.len;
				break;

			case (CKA_SUBJECT):
				value = certificate->derSubject.data;
				value_len = certificate->derSubject.len;
				break;

			case (CKA_SERIAL_NUMBER):
				value = certificate->serialNumber.data;
				value_len = certificate->serialNumber.len;
				break;

			case (CKA_CLASS):
				p11_ulong = CKO_CERTIFICATE;
				value = &p11_ulong;
				value_len = sizeof (CK_ULONG);
				break;

			case (CKA_LABEL):
				value = NULL_PTR;
				value_len = 0;
				break;

			case (CKA_ID):
				value = NULL_PTR;
				value_len = 0;
				break;

			default:
				current_attribute->ulValueLen = (CK_LONG) -1;
				continue;
				break;
		}

		rv = set_attribute_template (current_attribute, value, value_len);
	}

	return rv;
}

CK_RV C_SetAttributeValue (CK_SESSION_HANDLE hSession,	
		CK_OBJECT_HANDLE hObject,	
		CK_ATTRIBUTE_PTR pTemplate,	
		CK_ULONG ulCount)		
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit (CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,	
		CK_ULONG ulCount)		
{
	CK_ULONG i;
	GError *error = NULL;
	gboolean status, att_token = FALSE, att_certificate = FALSE;
	GList *addressbooks, *aux_addressbooks;
	EBookClient *client_addressbook;
	EBookClientCursor *cursor = NULL;
	gchar *query_string;
	gchar *label = NULL, *email = NULL;
	EBookQuery *final_query, *query = NULL;
	Session *session = NULL;

	EContactField sort_fields[] = { E_CONTACT_FAMILY_NAME, E_CONTACT_GIVEN_NAME };
	EBookCursorSortType sort_types[] = { E_BOOK_CURSOR_SORT_ASCENDING, E_BOOK_CURSOR_SORT_ASCENDING };

	if (!session_is_session_valid (hSession))
		return CKR_SESSION_HANDLE_INVALID;

	session = session_get_session (hSession);

	if (session->search_on_going) return CKR_OPERATION_ACTIVE;

	session->search_on_going = TRUE;

	/* Run through template looking for the attributes indicating a
	 * a search for certificates */
	for (i = 0; i < ulCount; i++) {
		switch (pTemplate[i].type) {
			/* Look only to attributes that concerns us */

			case CKA_TOKEN:
				if (*( (CK_BBOOL *)pTemplate[i].pValue) == CK_TRUE)
					att_token = TRUE;
				break;

			case CKA_CLASS:
				if (*( (CK_ATTRIBUTE_TYPE *)pTemplate[i].pValue) == CKO_CERTIFICATE)
					att_certificate = TRUE;
				break;

			case CKA_LABEL:
				label = malloc(pTemplate[i].ulValueLen+1);
				memcpy(label, pTemplate[i].pValue, pTemplate[i].ulValueLen);
				label[pTemplate[i].ulValueLen] = '\0';
				break;

			case CKA_NSS_EMAIL:
				email = malloc(pTemplate[i].ulValueLen);
				memcpy(email, pTemplate[i].pValue, pTemplate[i].ulValueLen);
				email[pTemplate[i].ulValueLen] = '\0';
				break;

			case CKA_ISSUER:
				session->att_issuer = TRUE;
				session->search_issuer.data = malloc(pTemplate[i].ulValueLen);
				memcpy(session->search_issuer.data, pTemplate[i].pValue, pTemplate[i].ulValueLen);
				session->search_issuer.len = pTemplate[i].ulValueLen;
				break;
		}
	}

	/* Check if searching for persistent certificates */
	if ( !(att_token && att_certificate) ) return CKR_OK;

	if (label && email) {
		query = e_book_query_orv ( 
				e_book_query_field_test (E_CONTACT_EMAIL, E_BOOK_QUERY_IS, label), 
				e_book_query_field_test (E_CONTACT_EMAIL, E_BOOK_QUERY_IS, email),
				NULL);
		free (label);
		free (email);
	} else if (label) {
		query = e_book_query_field_test (E_CONTACT_EMAIL, E_BOOK_QUERY_IS, label);
		free (label);
	} else if (email) {
		query = e_book_query_field_test (E_CONTACT_EMAIL, E_BOOK_QUERY_IS, email);
		free (email);
	} 

	final_query = e_book_query_andv (
			e_book_query_field_exists (E_CONTACT_X509_CERT),
			query,
			NULL);

	query_string = e_book_query_to_string (final_query);

	addressbooks = e_source_registry_list_enabled (registry, E_SOURCE_EXTENSION_ADDRESS_BOOK);
	aux_addressbooks = addressbooks;
	while (aux_addressbooks != NULL) {

		client_addressbook = (EBookClient *) e_book_client_connect_sync((ESource *) aux_addressbooks->data, NULL, &error);
		if (client_addressbook == NULL) {
			g_warning ("evolution-pkcs11: Failed to connect to addressbook: %s\n", error->message);
			g_error_free (error);

			aux_addressbooks = aux_addressbooks->next;
			continue;
		}

		status = e_book_client_get_cursor_sync (client_addressbook, query_string, sort_fields, sort_types, 2, &cursor, NULL, &error);
		if (status != TRUE) {
			g_warning ("evolution-pkcs11: Failed to get cursor from addressbook: %s\n", error->message);
			g_error_free (error);

			aux_addressbooks = aux_addressbooks->next;
			continue;
		}

		if (e_book_client_cursor_get_total (cursor) > 0) {
			session->cursor_list = g_slist_append (session->cursor_list, cursor);
		}

		g_object_unref (client_addressbook);
		aux_addressbooks = aux_addressbooks->next;
	}

	g_list_free_full (addressbooks, (GDestroyNotify) g_object_unref);
	e_book_query_unref (final_query);
	g_free (query_string);

	session->current_cursor = session->cursor_list;

	return CKR_OK;
}


CK_RV C_FindObjects (CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount,
		CK_ULONG_PTR pulObjectCount)
{
	gint n_results, n_objects;
	EBookClientCursor *cursor;
	GSList *results = NULL, *results_it;
	Object *obj;
	gboolean obj_exists;
	GError *error = NULL;
	Session *session = NULL;

	if (!session_is_session_valid (hSession))
		return CKR_SESSION_HANDLE_INVALID;

	session = session_get_session (hSession);

	if (!session->search_on_going) return CKR_OPERATION_NOT_INITIALIZED;

	if (phObject == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pulObjectCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (ulMaxObjectCount < 1)
		return CKR_BUFFER_TOO_SMALL;

	n_objects = 0;
	while (n_objects < ulMaxObjectCount && session->current_cursor != NULL) {
		results = NULL;
		cursor = session->current_cursor->data;
		n_results = e_book_client_cursor_step_sync(cursor,
				E_BOOK_CURSOR_STEP_MOVE | E_BOOK_CURSOR_STEP_FETCH,
				E_BOOK_CURSOR_ORIGIN_CURRENT,
				ulMaxObjectCount - n_objects,
				&results,
				NULL, &error);

		if (n_results < 0) {
			g_warning ("evolution-pkcs11: Failed to step cursor: %s\n", error->message);
			if (g_error_matches (error, E_CLIENT_ERROR, E_CLIENT_ERROR_OUT_OF_SYNC)) {
			} else if (g_error_matches (error, E_CLIENT_ERROR, E_CLIENT_ERROR_QUERY_REFUSED)) {
			} else {
			}
			g_error_free (error);
		}

		/* Check if cursor is depleated */
		if (n_results < ulMaxObjectCount - n_objects ) {
			/* Switch to next curson in the list */
			session->current_cursor = session->cursor_list->next;
		}

		/* Parse results */
		results_it = results;
		while (results_it != NULL) {
			/* Check if we already have an object created for this result */
			obj_exists = session_object_exists (session, results_it->data, &obj);

			if (!obj_exists)
				obj = new_object (results_it->data, object_handle_counter++);

			if (obj != NULL) {

				if (session->att_issuer == TRUE && 
						!compare_object_issuer (obj, &session->search_issuer) ) {
					/* Check if objects is of a specific issuer */
					free (obj);
					results_it = results_it->next;
					continue;
				}

				phObject[n_objects] = obj->handle;
				if (!obj_exists)
					session->objects_found = g_slist_append(session->objects_found, obj);
				n_objects++;
			}
			results_it = results_it->next;
		}

		if (results != NULL) g_slist_free_full (results, g_object_unref);
	}

	*pulObjectCount = n_objects;

	return CKR_OK;
}


CK_RV C_FindObjectsFinal (CK_SESSION_HANDLE hSession)
{
	Session *session = NULL;

	if (!session_is_session_valid (hSession))
		return CKR_SESSION_HANDLE_INVALID;

	session = session_get_session (hSession);

	if (!session->search_on_going) return CKR_OPERATION_NOT_INITIALIZED;

	session->search_on_going = FALSE;
	session->current_cursor = NULL;
	g_slist_free_full (session->cursor_list, g_object_unref);
	session->cursor_list = NULL;

	if (session->att_issuer) {
		session->att_issuer = FALSE;
		free (session->search_issuer.data);
		session->search_issuer.data = NULL;
		session->search_issuer.len = 0;

	}

	return CKR_OK;
}


CK_RV C_DigestInit (CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_Digest (CK_SESSION_HANDLE hSession,	
		CK_BYTE_PTR pData,	
		CK_ULONG ulDataLen,	
		CK_BYTE_PTR pDigest,	
		CK_ULONG_PTR pulDigestLen)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_DigestUpdate (CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,	
		CK_ULONG ulPartLen)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_DigestKey (CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DigestFinal (CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pDigest,	
		CK_ULONG_PTR pulDigestLen)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_SignInit (CK_SESSION_HANDLE hSession,		
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign (CK_SESSION_HANDLE hSession,	
		CK_BYTE_PTR pData,		
		CK_ULONG ulDataLen,	
		CK_BYTE_PTR pSignature,	
		CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_SignUpdate (CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,	
		CK_ULONG ulPartLen)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_SignFinal (CK_SESSION_HANDLE hSession,	
		CK_BYTE_PTR pSignature,	
		CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_SignRecoverInit (CK_SESSION_HANDLE hSession,	
		CK_MECHANISM_PTR pMechanism,	
		CK_OBJECT_HANDLE hKey)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover (CK_SESSION_HANDLE hSession,	
		CK_BYTE_PTR pData,	
		CK_ULONG ulDataLen,	
		CK_BYTE_PTR pSignature,	
		CK_ULONG_PTR pulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_EncryptInit (CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,	
		CK_OBJECT_HANDLE hKey)	
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_Encrypt (CK_SESSION_HANDLE hSession,	
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate (CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,	
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal (CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit (CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_Decrypt (CK_SESSION_HANDLE hSession,	
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DecryptUpdate (CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,	
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal (CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastPart,	
		     CK_ULONG_PTR pulLastPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate (CK_SESSION_HANDLE hSession,	
			    CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen,
			    CK_BYTE_PTR pEncryptedPart,	
			    CK_ULONG_PTR pulEncryptedPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate (CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,	
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate (CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen,
			  CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate (CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey (CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair (CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,	
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_RV C_WrapKey (CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey (CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey,
		  CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen,	
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey (CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_SeedRandom (CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom (CK_SESSION_HANDLE hSession,
		       CK_BYTE_PTR RandomData,
		       CK_ULONG ulRandomLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_GetFunctionStatus (CK_SESSION_HANDLE hSession)
{	
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction (CK_SESSION_HANDLE hSession)
{			
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_VerifyInit (CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism,	
		   CK_OBJECT_HANDLE hKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_Verify (CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_VerifyUpdate (CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_VerifyFinal (CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_VerifyRecoverInit (CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{		
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover (CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen,
		      CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{			
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_FUNCTION_LIST pkcs11_function_list = {
	{ 2, 20}, /* Note: NSS/Firefox ignores this version number and uses C_GetInfo() */
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};
