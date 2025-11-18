#ifndef _CIPHER_H_INCLUDED_6_28_2014_
#define _CIPHER_H_INCLUDED_6_28_2014_

#include "../include/sha/sha1.h"
#include "../include/sha/sha256.h"
#include "../include/sha/ripemd.h"

CIPHERSET gCipherSet;

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned int uint32_t;
typedef unsigned long long uint64;

typedef enum {
    CIPHER_NONE,
    CIPHER_CUSTOM,
    CIPHER_RC4,
    CIPHER_MD5,
    CIPHER_SHA1,
    CIPHER_SHA256,
    CIPHER_SHA384,
    CIPHER_SHA512,
    CIPHER_RSA
} eCipher;


//Forward declarations

//Cipher context
struct CTX;
typedef struct CTX  CTX;

struct CDAT;
typedef struct CDAT  CDAT;


typedef void (*fInit)(CTX* pCtx, const CDAT* pData);
typedef void (*fInput)(CTX* pCtx, const uchar* pData, uint nSize);
typedef void (*fDigest)(CTX* pCtx, uchar pDigest[]);
typedef void (*fHash)(const uchar* pData, uint nSize, uchar pDigest[]);

typedef void (*fCode)(CTX* pCtx, uchar* pData, uint nSize);


typedef struct CIPHER
{
    uint    eCipher;//Cipher type
    uint    cSize;  //Context size
    uint    dSize;  //Digest size
    const struct CDAT* pIData;

    fInit   Init;
    union {
    fInput  Input;
    fCode   Code;
    };
    fDigest Digest;
    fHash   Hash;
} CIPHER;

typedef struct RSA {
    void (*RsaEncrypt)(uchar* pText, const uchar* pPubKey, uint nPubExp, uint nKeyBytes);
    void (*RsaDecrypt)(uchar* pText, const uchar* pPubKey, const uchar* pPriKey, uint nKeyBytes);
} RSA;

typedef struct ECC {
    uint (*Verify)(const uchar digest[], const uchar pubKey[], const uchar R[], const uchar S[]);
} ECC;

typedef struct CIPHERSET {
    CIPHER  sha1;
    CIPHER  sha256;
    CIPHER  sha384;
    CIPHER  sha512;
    CIPHER  rip;
    RSA     rsa;
    ECC     p256;
} CIPHERSET;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern CIPHERSET gCipherSet;

void SetSha384(CIPHER* pCipher);
void SetSha512(CIPHER* pCipher);

void SetRsa(RSA* pRsa);

void SetP256(ECC* pEcc);

static const CIPHERSET* InitCiphers(CIPHERSET* pCipherSet) {
    if (pCipherSet == NULL) pCipherSet = &gCipherSet;

    SetSha1(&(pCipherSet->sha1));
    SetSha256(&(pCipherSet->sha256));
    SetSha384(&(pCipherSet->sha384));
    SetSha512(&(pCipherSet->sha512));
    SetRip(&(pCipherSet->rip));
    SetRsa(&(pCipherSet->rsa));
    SetP256(&(pCipherSet->p256));

    return pCipherSet;
}

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _CIPHER_H_INCLUDED_6_28_2014_
