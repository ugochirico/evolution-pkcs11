#include <nss3/cert.h>
#include <nss3/certt.h>
#include <nss3/pkcs11n.h>
#include <nss3/base64.h>

#ifndef __EVO_PKCS11_UTIL_H__
#define __EVO_PKCS11_UTIL_H__

CK_RV set_attribute_template (CK_ATTRIBUTE_PTR att, CK_VOID_PTR value, CK_ULONG value_len);

#endif /* __EVO_PKCS11_UTIL_H__ */
