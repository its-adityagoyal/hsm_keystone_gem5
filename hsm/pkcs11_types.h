#ifndef _PKCS11_TYPES_H_
#define _PKCS11_TYPES_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t   CK_BYTE;
typedef uint8_t   CK_CHAR;
typedef uint8_t   CK_UTF8CHAR;
typedef uint8_t   CK_BBOOL;
typedef uintptr_t CK_ULONG;
typedef intptr_t  CK_LONG;
typedef CK_ULONG  CK_FLAGS;

typedef void*     CK_VOID_PTR;
typedef CK_BYTE*  CK_BYTE_PTR;
typedef CK_CHAR*  CK_CHAR_PTR;
typedef CK_ULONG* CK_ULONG_PTR;

typedef CK_ULONG  CK_RV;
typedef CK_ULONG  CK_SLOT_ID;
typedef CK_ULONG  CK_SESSION_HANDLE;
typedef CK_ULONG  CK_OBJECT_HANDLE;
typedef CK_ULONG  CK_OBJECT_CLASS;
typedef CK_ULONG  CK_KEY_TYPE;
typedef CK_ULONG  CK_MECHANISM_TYPE;
typedef CK_ULONG  CK_ATTRIBUTE_TYPE;
typedef CK_ULONG  CK_NOTIFICATION;

typedef CK_SLOT_ID*        CK_SLOT_ID_PTR;
typedef CK_SESSION_HANDLE* CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE*  CK_OBJECT_HANDLE_PTR;

#define CK_TRUE  1
#define CK_FALSE 0

/* PKCS #11 Return Values */
#define CKR_OK                              0x00000000UL
#define CKR_CANCEL                          0x00000001UL
#define CKR_HOST_MEMORY                     0x00000002UL
#define CKR_SLOT_ID_INVALID                 0x00000003UL
#define CKR_GENERAL_ERROR                   0x00000005UL
#define CKR_FUNCTION_FAILED                 0x00000006UL
#define CKR_ARGUMENTS_BAD                   0x00000007UL
#define CKR_NO_EVENT                        0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS          0x00000009UL
#define CKR_CANT_LOCK                       0x0000000AUL
#define CKR_DEVICE_ERROR                    0x00000030UL
#define CKR_DEVICE_MEMORY                   0x00000031UL
#define CKR_KEY_HANDLE_INVALID              0x00000060UL
#define CKR_KEY_SIZE_RANGE                  0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063UL
#define CKR_KEY_NOT_NEEDED                  0x00000064UL
#define CKR_KEY_CHANGED                     0x00000065UL
#define CKR_KEY_NEEDED                      0x00000066UL
#define CKR_KEY_INDIGESTIBLE                0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED      0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE               0x00000069UL
#define CKR_KEY_UNEXTRACTABLE               0x0000006AUL
#define CKR_MECHANISM_INVALID               0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID         0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID           0x00000082UL
#define CKR_OPERATION_ACTIVE                0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091UL
#define CKR_SIGNATURE_INVALID               0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE             0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE             0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT           0x000000D1UL
#define CKR_DATA_INVALID                    0x000000E0UL
#define CKR_DATA_LEN_RANGE                  0x000000E1UL
#define CKR_BUFFER_TOO_SMALL                0x00000150UL
#define CKR_SESSION_HANDLE_INVALID          0x00000003UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED  0x000000B2UL
#define CKR_SESSION_READ_ONLY               0x000000B5UL
#define CKR_SESSION_EXISTS                  0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS        0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS    0x000000B8UL
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED    0x00000191UL

/* PKCS #11 Mechanism Types */
#define CKM_RSA_PKCS_KEY_PAIR_GEN           0x00000000UL
#define CKM_RSA_PKCS                        0x00000001UL
#define CKM_SHA256                          0x00000250UL
#define CKM_SHA256_HMAC                     0x00000251UL
#define CKM_SHA256_HMAC_KEY_GEN             0x00000252UL
#define CKM_AES_KEY_GEN                     0x00001080UL
#define CKM_AES_ECB                         0x00001081UL
#define CKM_AES_CBC                         0x00001082UL
#define CKM_AES_CBC_PAD                     0x00001085UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN         0x00001055UL
#define CKM_EDDSA                           0x00001057UL

/* PKCS #11 Key Types */
#define CKK_RSA                             0x00000000UL
#define CKK_EC                              0x00000003UL
#define CKK_GENERIC_SECRET                  0x00000010UL
#define CKK_AES                             0x0000001FUL
#define CKK_EC_EDWARDS                      0x00000040UL

/* PKCS #11 Attributes */
#define CKA_CLASS                           0x00000000UL
#define CKA_TOKEN                           0x00000001UL
#define CKA_PRIVATE                         0x00000002UL
#define CKA_LABEL                           0x00000003UL
#define CKA_APPLICATION                     0x00000004UL
#define CKA_VALUE                           0x00000011UL
#define CKA_OBJECT_ID                       0x00000012UL
#define CKA_KEY_TYPE                        0x00000100UL
#define CKA_VALUE_LEN                       0x00000161UL
#define CKA_ENCRYPT                         0x00000104UL
#define CKA_DECRYPT                         0x00000105UL
#define CKA_SIGN                            0x00000108UL
#define CKA_VERIFY                          0x0000010AUL

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_INFO* CK_INFO_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM* CK_MECHANISM_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE* CK_ATTRIBUTE_PTR;

typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

#ifdef __cplusplus
}
#endif

#endif /* _PKCS11_TYPES_H_ */
