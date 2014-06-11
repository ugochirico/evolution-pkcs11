#include "pkcs11.h"
#include <nss3/certt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern CK_FUNCTION_LIST pkcs11_function_list;

static CK_UTF8CHAR manufacturerID[] =		"Yuuma Sato                      ";
static CK_UTF8CHAR libraryDescription[] =	"CertModule PKCS#11 API          ";

static unsigned char sato_certificate[] = {
	0x30,0x82,0x03,0xef,0x30,0x82,0x01,0xd7,0x02,0x01,0x01,0x30,0x0d,0x06,0x09,0x2a,
	0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x30,0x6c,0x31,0x0b,0x30,0x09,
	0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x42,0x52,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,
	0x04,0x08,0x0c,0x02,0x53,0x50,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x07,0x0c,
	0x05,0x43,0x61,0x6d,0x70,0x73,0x31,0x1c,0x30,0x1a,0x06,0x03,0x55,0x04,0x0a,0x0c,
	0x13,0x44,0x65,0x66,0x61,0x75,0x6c,0x74,0x20,0x43,0x6f,0x6d,0x70,0x61,0x6e,0x79,
	0x20,0x4c,0x74,0x64,0x31,0x0d,0x30,0x0b,0x06,0x03,0x55,0x04,0x0b,0x0c,0x04,0x48,
	0x6f,0x6d,0x65,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x0c,0x0a,0x41,0x75,
	0x74,0x6f,0x72,0x69,0x64,0x61,0x64,0x65,0x30,0x1e,0x17,0x0d,0x31,0x34,0x30,0x33,
	0x30,0x33,0x30,0x35,0x31,0x34,0x34,0x37,0x5a,0x17,0x0d,0x31,0x35,0x30,0x33,0x30,
	0x33,0x30,0x35,0x31,0x34,0x34,0x37,0x5a,0x30,0x81,0x92,0x31,0x0b,0x30,0x09,0x06,
	0x03,0x55,0x04,0x06,0x13,0x02,0x42,0x52,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,
	0x08,0x0c,0x02,0x53,0x50,0x31,0x0e,0x30,0x0c,0x06,0x03,0x55,0x04,0x07,0x0c,0x05,
	0x43,0x61,0x6d,0x70,0x73,0x31,0x1c,0x30,0x1a,0x06,0x03,0x55,0x04,0x0a,0x0c,0x13,
	0x44,0x65,0x66,0x61,0x75,0x6c,0x74,0x20,0x43,0x6f,0x6d,0x70,0x61,0x6e,0x79,0x20,
	0x4c,0x74,0x64,0x31,0x0f,0x30,0x0d,0x06,0x03,0x55,0x04,0x0b,0x0c,0x06,0x51,0x75,
	0x61,0x72,0x74,0x6f,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x0c,0x0a,0x53,
	0x61,0x74,0x6f,0x20,0x59,0x75,0x75,0x6d,0x61,0x31,0x22,0x30,0x20,0x06,0x09,0x2a,
	0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01,0x16,0x13,0x73,0x61,0x74,0x6f,0x79,0x75,
	0x75,0x6d,0x61,0x40,0x67,0x6d,0x61,0x69,0x6c,0x2e,0x63,0x6f,0x6d,0x30,0x81,0x9f,
	0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,
	0x81,0x8d,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xc0,0xb3,0x96,0x67,0xa4,0x76,
	0xbb,0x54,0x70,0x71,0x6f,0xab,0x44,0xa5,0xfb,0xd5,0x58,0x42,0x24,0x21,0x5c,0xd1,
	0x6f,0xb7,0x96,0x0c,0x2c,0xc4,0x0a,0xc7,0xa9,0xe2,0x1c,0x99,0x13,0x82,0xba,0x2a,
	0x96,0x3f,0x76,0x89,0x52,0xab,0x39,0xfa,0x5b,0x7f,0xb8,0x87,0xde,0x5c,0x9f,0x23,
	0xca,0x72,0x1a,0xa9,0x80,0x80,0xb3,0xe0,0x28,0xee,0x64,0x72,0x4b,0x84,0x01,0x54,
	0x3e,0x9c,0xe0,0x75,0x4b,0xd1,0x43,0xa1,0xd5,0x3a,0x13,0x08,0x89,0x13,0xcb,0x7c,
	0x1c,0x29,0x4c,0x4b,0x26,0xe5,0x5b,0x22,0xd3,0x29,0x97,0x3a,0xab,0xc0,0x4f,0xc8,
	0xb4,0x4f,0xf8,0x72,0xd6,0x2c,0xbb,0x05,0x50,0x78,0x30,0x4c,0x45,0xac,0x35,0x2a,
	0x52,0x9e,0xe9,0xb0,0xfb,0x8a,0x77,0x3c,0x6c,0xad,0x02,0x03,0x01,0x00,0x01,0x30,
	0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05,0x05,0x00,0x03,0x82,
	0x02,0x01,0x00,0xbc,0x60,0x42,0x73,0x51,0x0b,0x66,0xb9,0x1d,0xbf,0x81,0x0a,0xbd,
	0x33,0x3f,0xa8,0xad,0x52,0x03,0xeb,0x33,0x0c,0xa4,0xfb,0x7d,0x50,0x5c,0xf3,0xc8,
	0x96,0x76,0x10,0x5a,0x20,0xa2,0xdc,0x11,0xf5,0xf4,0xd6,0x42,0x42,0x46,0x23,0xb5,
	0x98,0xc1,0xba,0x5f,0x8b,0x76,0xa4,0xbf,0x62,0x28,0x66,0x87,0x70,0xf9,0xc4,0x9c,
	0x2a,0xd3,0xcc,0xb6,0x54,0x8d,0xb5,0x41,0x43,0x7c,0x15,0x12,0x0b,0x34,0x77,0xca,
	0xe4,0xc1,0x00,0x1b,0xf9,0xed,0x73,0xea,0x1a,0x78,0x47,0xa0,0xd6,0xd6,0xa2,0x55,
	0x2f,0x12,0x80,0x67,0x1a,0x73,0xa6,0xda,0x48,0xba,0x4b,0x77,0x55,0x23,0x17,0xcd,
	0xb2,0x1c,0x54,0x29,0x60,0x64,0x9c,0xe7,0xb7,0x79,0x26,0x6d,0x22,0xa2,0x60,0x7e,
	0x11,0x59,0xaf,0xef,0x8b,0xe0,0x06,0x46,0x77,0x3f,0x4c,0xcf,0x16,0xf2,0x7b,0xaa,
	0x8d,0x32,0xb4,0x90,0x57,0x02,0xaf,0x8f,0x28,0xb7,0x83,0x63,0xa2,0x5b,0x9f,0x7e,
	0x90,0x5a,0x25,0x9f,0xc0,0x02,0x3b,0xe1,0x62,0xc9,0xd0,0xa7,0x31,0xf2,0x9a,0x56,
	0x03,0x37,0x85,0x0c,0x01,0x61,0x01,0x28,0x46,0x43,0xd5,0xa5,0x45,0xe8,0x84,0x16,
	0x11,0x99,0x83,0x49,0x1a,0x81,0xca,0xcb,0x9f,0x56,0x5a,0xe7,0x17,0x48,0x65,0x18,
	0xf6,0x64,0x50,0x09,0xb4,0x46,0xbf,0x55,0x35,0x75,0xe1,0x7c,0xdf,0x1f,0xb2,0x83,
	0xf0,0x6b,0xa4,0x8a,0x32,0xa8,0x34,0xba,0xe3,0xa9,0xca,0xe6,0x1e,0x2c,0xf1,0xf4,
	0xc4,0x3c,0x97,0x93,0xbd,0x38,0xc2,0xa5,0x4b,0x5a,0x42,0x1a,0xa9,0x6c,0x6c,0x05,
	0x4e,0xed,0xcb,0xf1,0x32,0x64,0xc4,0xcb,0xa8,0x89,0x49,0x5c,0xf9,0x63,0x33,0x57,
	0x5e,0xba,0x84,0x43,0x5a,0x34,0x67,0x16,0xde,0xe2,0x72,0xec,0x5d,0xd4,0x04,0x3d,
	0x7d,0x41,0xde,0x1d,0x16,0xbf,0x88,0xd2,0xe5,0xae,0x34,0x7c,0x74,0xff,0x67,0x6c,
	0x65,0xbd,0xaf,0x99,0x60,0xdd,0x67,0x70,0x81,0x2b,0xb9,0xfc,0x0c,0xa2,0x43,0x50,
	0x00,0xcb,0x38,0xfb,0x4b,0x0a,0x49,0xd0,0x6f,0x0f,0x2e,0x12,0x9e,0x95,0xfb,0x13,
	0x81,0x9b,0x65,0x8a,0xbc,0x03,0xe1,0x1f,0xd0,0x51,0xad,0xb7,0xc7,0xd0,0x69,0x35,
	0xc8,0x5e,0x0c,0x0b,0xd7,0x26,0x7f,0xc2,0xdb,0xe0,0xa9,0x56,0x51,0x70,0x14,0xe7,
	0xa0,0xe8,0x9d,0x14,0xfa,0x47,0xda,0xba,0xde,0x15,0x83,0xdc,0xb2,0x0d,0xa6,0x39,
	0xe2,0x75,0x6a,0x6a,0x89,0x54,0x38,0x6b,0x5f,0xc8,0x28,0x2a,0xeb,0xfe,0x16,0x9d,
	0x4e,0xa1,0x52,0x5b,0x17,0x90,0x0b,0x68,0xa0,0xb2,0x5b,0xe5,0x32,0x0b,0x98,0x6f,
	0x97,0xe1,0x43,0x51,0xc9,0x47,0xbd,0x24,0xc5,0x76,0x7b,0x5d,0xd8,0x69,0xa2,0x88,
	0x43,0xf7,0x49,0xbc,0xf7,0x21,0xa7,0x79,0xd2,0x81,0xc5,0xc3,0x7d,0x09,0xaa,0x2e,
	0x3c,0x55,0xdf,0x25,0xdb,0x2f,0xbd,0x4a,0xd8,0xf8,0x3b,0x4a,0x47,0xc9,0xfd,0x55,
	0x7e,0x41,0x72,0x9d,0x30,0x91,0xdb,0xba,0x2f,0x43,0x34,0x6a,0x74,0x70,0xa2,0xc3,
	0xce,0x2e,0xa0,0x87,0x33,0xff,0xf8,0xcf,0xfb,0xef,0x05,0x2c,0x4b,0xe2,0x8d,0xbb,
	0xa8,0x78,0xaf,0x46,0x02,0xbe,0xdb,0xf6,0x2d,0xd1,0xf0,0x32,0x96,0xe3,0x24,0x1a,
	0x82,0x4a,0xdd};

static unsigned char issuer_name[] = {
	0x30,0x6C,0x31,0x0B,0x30,0x09,0x06,0x03,
	0x55,0x04,0x06,0x13,0x02,0x42,0x52,0x31,
	0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x08,
	0x0C,0x02,0x53,0x50,0x31,0x0E,0x30,0x0C,
	0x06,0x03,0x55,0x04,0x07,0x0C,0x05,0x43,
	0x61,0x6D,0x70,0x73,0x31,0x1C,0x30,0x1A,
	0x06,0x03,0x55,0x04,0x0A,0x0C,0x13,0x44,
	0x65,0x66,0x61,0x75,0x6C,0x74,0x20,0x43,
	0x6F,0x6D,0x70,0x61,0x6E,0x79,0x20,0x4C,
	0x74,0x64,0x31,0x0D,0x30,0x0B,0x06,0x03,
	0x55,0x04,0x0B,0x0C,0x04,0x48,0x6F,0x6D,
	0x65,0x31,0x13,0x30,0x11,0x06,0x03,0x55,
	0x04,0x03,0x0C,0x0A,0x41,0x75,0x74,0x6F,
	0x72,0x69,0x64,0x61,0x64,0x65
};

static unsigned char subject_name[] = {
	0x30,0x81,0x92,0x31,0x0B,0x30,0x09,0x06,
	0x03,0x55,0x04,0x06,0x13,0x02,0x42,0x52,
	0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,
	0x08,0x0C,0x02,0x53,0x50,0x31,0x0E,0x30, 
	0x0C,0x06,0x03,0x55,0x04,0x07,0x0C,0x05,
	0x43,0x61,0x6D,0x70,0x73,0x31,0x1C,0x30, 
	0x1A,0x06,0x03,0x55,0x04,0x0A,0x0C,0x13,
	0x44,0x65,0x66,0x61,0x75,0x6C,0x74,0x20, 
	0x43,0x6F,0x6D,0x70,0x61,0x6E,0x79,0x20,
	0x4C,0x74,0x64,0x31,0x0F,0x30,0x0D,0x06, 
	0x03,0x55,0x04,0x0B,0x0C,0x06,0x51,0x75,
	0x61,0x72,0x74,0x6F,0x31,0x13,0x30,0x11, 
	0x06,0x03,0x55,0x04,0x03,0x0C,0x0A,0x53,
	0x61,0x74,0x6F,0x20,0x59,0x75,0x75,0x6D, 
	0x61,0x31,0x22,0x30,0x20,0x06,0x09,0x2A,
	0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x01, 
	0x16,0x13,0x73,0x61,0x74,0x6F,0x79,0x75,
	0x75,0x6D,0x61,0x40,0x67,0x6D,0x61,0x69, 
	0x6C,0x2E,0x63,0x6F,0x6D
};

/* Internal Objects */

/* Hard coded certificate */
#define HARD_CERT_HANDLE 0x90910A0B
static CK_OBJECT_HANDLE h_hard_cert = HARD_CERT_HANDLE;
static CK_ATTRIBUTE_PTR obj_hard_cert;
static CK_ULONG att_count;

static CK_ULONG already_searched;

CK_RV C_Initialize (CK_VOID_PTR pInitArgs)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;
	int d;
	CK_ATTRIBUTE_PTR obj;

	CK_BBOOL b;
	char *sato_certificate_pem;
	CERTCertificate *cert = NULL;

	/* Create hardcoded certificate */
	att_count = 10;
	obj = malloc (sizeof (CK_ATTRIBUTE) * att_count);

	i = 0;
	obj[i].type = CKA_TOKEN;
	obj[i].ulValueLen = sizeof (CK_BBOOL);
	obj[i].pValue = malloc (sizeof (CK_BBOOL));
	*(CK_OBJECT_CLASS *)(obj[i].pValue) = CK_TRUE;

	i = 1;
	obj[i].type = CKA_CLASS;
	obj[i].ulValueLen = sizeof (CK_OBJECT_CLASS);
	obj[i].pValue = malloc (sizeof (CK_OBJECT_CLASS));
	*(CK_OBJECT_CLASS *)(obj[i].pValue) = CKO_CERTIFICATE;

	i = 2;
	obj[i].type = CKA_CERTIFICATE_TYPE;
	obj[i].ulValueLen = sizeof (CK_CERTIFICATE_TYPE);
	obj[i].pValue = malloc (sizeof (CK_CERTIFICATE_TYPE));
	*(CK_CERTIFICATE_TYPE *)(obj[i].pValue) = CKC_X_509;

	i = 3;
	obj[i].type = CKA_TRUSTED;
	obj[i].ulValueLen = sizeof (CK_BBOOL);
	obj[i].pValue = malloc (sizeof (CK_BBOOL));
	*(CK_BBOOL *)(obj[i].pValue) = CK_TRUE;

	i = 4;
	obj[i].type = CKA_CERTIFICATE_CATEGORY;
	obj[i].ulValueLen = sizeof (CK_ULONG);
	obj[i].pValue = malloc (sizeof (CK_ULONG));
	*(CK_ULONG	*)(obj[i].pValue) = 0;

	i = 5;
	obj[i].type = CKA_CHECK_VALUE;
	obj[i].ulValueLen = 3;
	obj[i].pValue = malloc (3);
	// 3 first bytes of sha-1
	// *(CK_BYTE_PTR_PTRobj[3].pValue) = 0;

	/* add X509 Certificate Object Attributes, Table 24 */

	i = 6;
	obj[i].type = CKA_ISSUER;
	obj[i].ulValueLen = strlen (issuer_name);
	obj[i].pValue = malloc (obj[i].ulValueLen);
	memcpy (obj[i].pValue, issuer_name, obj[i].ulValueLen);
	
	i = 7;
	obj[i].type = CKA_VALUE;
	obj[i].ulValueLen = 1011; 
	obj[i].pValue = malloc (obj[i].ulValueLen);
	memcpy (obj[i].pValue, sato_certificate, obj[i].ulValueLen);
	
	i = 8;
	obj[i].type = CKA_SUBJECT;
	obj[i].ulValueLen = strlen (subject_name);
	obj[i].pValue = malloc (obj[i].ulValueLen);
	memcpy (obj[i].pValue, subject_name, obj[i].ulValueLen);
	
	i = 9;
	obj[i].type = CKA_SERIAL_NUMBER;
	obj[i].ulValueLen = 3;
	obj[i].pValue = malloc (obj[i].ulValueLen);
	((CK_ULONG_PTR) obj[i].pValue)[0] = 0x02;
	((CK_ULONG_PTR) obj[i].pValue)[1] = 0x01;
	((CK_ULONG_PTR) obj[i].pValue)[2] = 0x01;
	

	obj_hard_cert = obj;

	/* Escrever funções genéricas de template? */

	return rv;
}

CK_RV C_Finalize (CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i;
	//Close connection with addressbook sources

	/* Free hardcoded_certificate */
	for (i = 0; i < att_count; i++) {
		free (obj_hard_cert[i].pValue);
	}

	free (obj_hard_cert);	
	
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

	CK_ULONG i;

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
	CK_RV rv;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION))
		return CKR_ARGUMENTS_BAD;

	*phSession = (CK_ULONG) 1;

	return CKR_OK;
}


CK_RV C_CloseSession (CK_SESSION_HANDLE hSession)
{			
	CK_RV rv;

	return CKR_OK;
}

CK_RV C_CloseAllSessions (CK_SLOT_ID slotID)
{			
	CK_RV rv = CKR_OK;

	return rv;
}

CK_RV C_GetSessionInfo (CK_SESSION_HANDLE hSession,
		       CK_SESSION_INFO_PTR pInfo)
{			
	CK_RV rv;

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
	return CKR_OK;
}

CK_RV C_Logout (CK_SESSION_HANDLE hSession)
{
	return CKR_OK;
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
	CK_ULONG i, j, idx;
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE_PTR current_attribute;

	if (hObject != 0x90910A0B){
		return CKR_OBJECT_HANDLE_INVALID;
	}

	for (i = 0; i < ulCount; i++){
		current_attribute = &pTemplate[i];
		switch (current_attribute->type){

			case (CKA_TOKEN):
				idx = 0;
				break;

			// case (CKA_LABEL):
				// current_attribute->ulValueLen = -1;
				// break;

			case (CKA_VALUE):
				idx = 7;
				break;

			case (CKA_CERTIFICATE_TYPE):
				idx = 2;
				break;

			case (CKA_ISSUER):
				idx = 6;
				break;

			case (CKA_SUBJECT):
				idx = 8;
				break;

			case (CKA_SERIAL_NUMBER):
				idx = 9;
				break;

			default:
				current_attribute->ulValueLen = (CK_LONG) -1;
				continue;
				break;
		}

		if (current_attribute->pValue != NULL_PTR){
			if (current_attribute->ulValueLen >= obj_hard_cert[idx].ulValueLen){
				memcpy (current_attribute->pValue, obj_hard_cert[idx].pValue, obj_hard_cert[idx].ulValueLen);
			}else{
				rv = CKR_BUFFER_TOO_SMALL;
			}
		}
		current_attribute->ulValueLen = obj_hard_cert[idx].ulValueLen;
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

static CK_ATTRIBUTE_PTR search_template;
static CK_ULONG search_template_len;


CK_RV C_FindObjectsInit (CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,	
		CK_ULONG ulCount)		
{
	CK_ULONG i;


	search_template = malloc (sizeof (CK_ATTRIBUTE) * ulCount);

	for (i = 0; i < ulCount; i++) {
		search_template[i].type = pTemplate[i].type;

		search_template[i].pValue = malloc (pTemplate[i].ulValueLen);
		memcpy (search_template[i].pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);

		search_template[i].ulValueLen = pTemplate[i].ulValueLen;
	}	
	search_template_len = ulCount;

	already_searched = 0;

	return CKR_OK;
}



CK_RV C_FindObjects (CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount,
		CK_ULONG_PTR pulObjectCount)	
{
	CK_BBOOL match_token = CK_FALSE, match_email = CK_FALSE, match_class = CK_FALSE;
	CK_ULONG i;

	if (phObject == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pulObjectCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (ulMaxObjectCount < 1)
		return CKR_BUFFER_TOO_SMALL;

	*pulObjectCount = 0;

	/* For now, the only known object is the hardcoded certificate */	
	for (i = 0; i < search_template_len; i++) {
		if (search_template[i].type == CKA_TOKEN) {
			if (*( (CK_BBOOL *)search_template[i].pValue) == CK_TRUE)
				match_token = CK_TRUE;
		} else if (search_template[i].type == CKA_CLASS) {
			if (*( (CK_ATTRIBUTE_TYPE *)search_template[i].pValue) == CKO_CERTIFICATE)
				match_class = CK_TRUE;
		} /*else if (search_template[i].type == CKA_NSS_EMAIL) {
			if (!memcmp (search_template[i].pValue, &"satoyuuma@gmail.com", search_template[i].ulValueLen))
				match_email = CK_TRUE;
		}*/
	}

	if (match_token && match_class) {
		*pulObjectCount = 1;
		*phObject = HARD_CERT_HANDLE;
	}

	return CKR_OK;
}



CK_RV C_FindObjectsFinal (CK_SESSION_HANDLE hSession)
{
	CK_ULONG i;

	for (i = 0; i < search_template_len; i++) {
		free (search_template[i].pValue);
	}
	free (search_template);
	search_template = NULL;

	return CKR_OK;
}


/*
 * Below here all functions are wrappers to pass all object attribute and method
 * handling to appropriate object layer.
 */
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
