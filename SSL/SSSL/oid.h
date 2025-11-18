#ifndef OID_H_INCLUDED
#define OID_H_INCLUDED

typedef unsigned char uchar;
typedef unsigned int  uint;

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

enum OID
{
 OID_UNKNOWN = 0,
 OID_RSAA    = 1,
 OID_EMAIL   = 2,
 OID_EMAIL2  = 3,

 OID_HASH_MD2_RSA      = 8,
 OID_HASH_MD4_RSA      = 9,
 OID_HASH_MD5_RSA      = 10,
 OID_HASH_SHA1_RSA     = 11,
 OID_HASH_SHA256_RSA   = 12,
 OID_HASH_SHA384_RSA   = 13,
 OID_HASH_SHA512_RSA   = 14,
 OID_HASH_SHA256_ECDSA = 15,
 OID_HASH_SHA384_ECDSA = 16,

 OID_ECCGROUP_SECP256R1 = 17,
 OID_ECGROUP_SECP384R1  = 18,

 OID_PUBKEY_RSA = 24,
 OID_PUBKEY_ECC = 25,

 OID_X509V3_KEY_USAGE         = 32,
 OID_X509V3_SUBJECT_ALTNAME   = 33,
 OID_X509V3_BASIC_CONSTRAINTS = 34,

 OID_NAME_COMMON  = 64,
 OID_NAME_UNIT    = 65,
 OID_NAME_ORG     = 66,
 OID_NAME_LOCAL   = 67,
 OID_NAME_STATE   = 68,
 OID_NAME_COUNTRY = 69,

 OID_DIGEST_MD2    = 72,
 OID_DIGEST_MD4    = 73,
 OID_DIGEST_MD5    = 74,
 OID_DIGEST_SHA1   = 75,
 OID_DIGEST_SHA256 = 76
};

struct OIDDATA
{
 OID   oid;
 uint  nDataSize;
 uchar data[16];
};


static const OIDDATA gOIDs[] = {
    {                // OID = 06 09 2A 86 48 86 F7 0D 01 01 01
     OID_PUBKEY_RSA, // Comment = PKCS #1
     9,              // Description = rsaEncryption (1 2 840 113549 1 1 1)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}},
    {                  // OID = 06 09 2A 86 48 86 F7 0D 01 01 02
     OID_HASH_MD2_RSA, // Comment = PKCS #1
     9,                // Description = md2withRSAEncryption (1 2 840 113549 1 1 2)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02}},
    {                  // OID = 06 09 2A 86 48 86 F7 0D 01 01 03
     OID_HASH_MD4_RSA, // Comment = PKCS #1
     9,                // Description = md4withRSAEncryption (1 2 840 113549 1 1 3)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02}},
    {                  // OID = 06 09 2A 86 48 86 F7 0D 01 01 04
     OID_HASH_MD5_RSA, // Comment = PKCS #1
     9,                // Description = md5withRSAEncryption (1 2 840 113549 1 1 4)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04}},
    {                   // OID = 06 09 2A 86 48 86 F7 0D 01 01 05
     OID_HASH_SHA1_RSA, // Comment = PKCS #1
     9,                 // Description = sha1withRSAEncryption (1 2 840 113549 1 1 5)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05}},
    {                     // OID = 06 09 2A 86 48 86 F7 0D 01 01 0B
     OID_HASH_SHA256_RSA, // Comment = PKCS #1
     9,                   // Description = sha1withRSAEncryption (1 2 840 113549 1 1 11)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}},
    {                     // OID = 06 09 2A 86 48 86 F7 0D 01 01 0C
     OID_HASH_SHA384_RSA, // Comment = PKCS#1 http://www.oid-info.com/get/1.2.840.113549.1.1.12
     9,                   // Description = sha384WithRSAEncryption ((1 2 840 113549 1 1 12))
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C}},
    {                     // OID = 06 09 2A 86 48 86 F7 0D 01 01 0D
     OID_HASH_SHA512_RSA, // Comment = PKCS#1 http://www.oid-info.com/get/1.2.840.113549.1.1.12
     9,                   // Description = sha512WithRSAEncryption ((1 2 840 113549 1 1 13))
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D}},
    {                       // OID = 06 08 2A 86 48 CE 3D 04 03 02
     OID_HASH_SHA256_ECDSA, // Comment: http://www.oid-info.com/get/1.2.840.10045.4.3.2
     8,                     // Description = ecdsa-with-SHA256 (1 2 840 10045 4 3 2)
     {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}},
    {                       // OID = 06 08 2A 86 48 CE 3D 04 03 03
     OID_HASH_SHA384_ECDSA, // Comment: http://www.oid-info.com/get/1.2.840.10045.4.3.3
     8,                     // Description = ecdsa-with-SHA384 (1 2 840 10045 4 3 3)
     {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03}},
    {                // OID = 06 07 2a 86 48 ce 3d 02 01
     OID_PUBKEY_ECC, // Comment: http://www.oid-info.com/get/1.2.840.10045.2.1
     7,              // 2a 86 48 ce 3d 02 01 // Description = ecPublicKey(1 2 840 10045 2 1)
     {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}},
    {                        // OID = 06 08 2A 86 48 CE 3D 03 01 07
     OID_ECCGROUP_SECP256R1, // Comment: http://www.oid-info.com/get/1.2.840.10045.3.1.7
     8,                      // Description: prime256v1 aka secp256r1 (1 2 840 10045 3 1 7)
     {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}},
    {                       // OID = 06 05 2B 81 04 00 22
     OID_ECGROUP_SECP384R1, // Comment: http://www.oid-info.com/get/1.3.132.0.34
     5,                     // Description: aka secp384r1 (1 3 132 0 34)
     {0x2B, 0x81, 0x04, 0x00, 0x22}},
    {                      // OID = 06 03 55 1D 0F
     OID_X509V3_KEY_USAGE, // Comment = https://tools.ietf.org/html/rfc5280#section-4.2.1.3
     3,                    // Description = keyUsage (2 5 29 15)
     {0x55, 0x1D, 0x0F}},
    {                            // OID = 06 03 55 1D 11 http://www.oid-info.com/get/2.5.29.17
     OID_X509V3_SUBJECT_ALTNAME, // Comment = https://tools.ietf.org/html/rfc5280#section-4.2.1.6
     3,                          // Description = basicConstraints (2 5 29 17)
     {0x55, 0x1D, 0x11}},
    {                              // OID = 06 03 55 1D 13
     OID_X509V3_BASIC_CONSTRAINTS, // Comment = https://tools.ietf.org/html/rfc5280#section-4.2.1.9
     3,                            // Description = basicConstraints (2 5 29 19)
     {0x55, 0x1D, 0x13}},
    {                 // OID = 06 03 55 04 03
     OID_NAME_COMMON, // Comment = X.520 id-at (2 5 4)
     3,               // Description = commonName (2 5 4 3)
     {0x55, 0x04, 0x03}},
    {              // OID = 06 03 55 04 0A
     OID_NAME_ORG, // Comment = X.520 id-at (2 5 4)
     3,            // Description = organizationName (2 5 4 10)
     {0x55, 0x04, 0x0A}},
    {               // OID = 06 03 55 04 0B
     OID_NAME_UNIT, // Comment = X.520 id-at (2 5 4)
     3,             // Description = organizationalUnitName (2 5 4 11)
     {0x55, 0x04, 0x0B}},
    {                // OID = 06 03 55 04 07
     OID_NAME_LOCAL, // Comment = X.520 id-at (2 5 4)
     3,              // Description = localityName (2 5 4 7)
     {0x55, 0x04, 0x07}},
    {                // OID = 06 03 55 04 08
     OID_NAME_STATE, // Comment = X.520 id-at (2 5 4)
     3,              // Description = stateOrProvinceName (2 5 4 8)
     {0x55, 0x04, 0x08}},
    {                  // OID = 06 03 55 04 06
     OID_NAME_COUNTRY, // Comment = X.520 id-at (2 5 4)
     3,                // Description = countryName (2 5 4 6)
     {0x55, 0x04, 0x06}},
    {                // OID = 06 08 2A 86 48 86 F7 0D 02 02
     OID_DIGEST_MD2, // Comment = RSADSI digestAlgorithm
     8,              // Description = md2 (1 2 840 113549 2 2)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02}},
    {                // OID = 06 08 2A 86 48 86 F7 0D 02 04
     OID_DIGEST_MD4, // Comment = RSADSI digestAlgorithm
     8,              // Description = md4 (1 2 840 113549 2 4)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x04}},
    {                // OID = 06 08 2A 86 48 86 F7 0D 02 05
     OID_DIGEST_MD5, // Comment = RSADSI digestAlgorithm
     8,              // Description = md5 (1 2 840 113549 2 5)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05}},
    {                 // OID = 06 05 2B 0E 03 02 1A
     OID_DIGEST_SHA1, // Comment = OIW
     5,               // Description = sha1 (1 3 14 3 2 26)
     {0x2B, 0x0E, 0x03, 0x02, 0x1A}},
    {                   // OID = 06 09 60 86 48 01 65 03 04 02 01
     OID_DIGEST_SHA256, // Comment = SHA-256 nistAlgorithms
     9,                 // Description = sha-256 (2.16.840.1.101.3.4.2.1)
     {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}},
    {           // OID = 06 09 2A 86 48 86 F7 0D 01 09 01
     OID_EMAIL, // Comment = PKCS #9.  Deprecated, use an altName extension instead
     9,         // Description = emailAddress (1 2 840 113549 1 9 1)
     {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01}},
    {            // OID = 06 0A 2B 06 01 04 01 2A 02 0B 02 01
     OID_EMAIL2, // Comment = Unknown
     10,         // Description = emailAddress (1 3 6 1 4 1 42 2 11 2 1)
     {0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x0B, 0x02, 0x01}},
    {OID_UNKNOWN, 0, {0x00}}};

//---------------------------------------------------------------------------------------------------
OID GetOID(const uchar* pMsg, uint cbBytes)
{
 for (const OIDDATA* pOID = gOIDs; pOID->oid != OID_UNKNOWN; pOID++)
 {
  if (cbBytes != pOID->nDataSize) continue;

  uint i;
  for (i = 0; i < pOID->nDataSize; i++)
   if (pMsg[i] != pOID->data[i]) break;
  if (i == cbBytes) return pOID->oid;
 }

 return OID_UNKNOWN;
}
//---------------------------------------------------------------------------------------------------
uint SetOID(uchar* pBuff, OID oid)
{
 for(const OIDDATA* pOID = gOIDs; pOID->oid != OID_UNKNOWN; pOID++)
 {
  if(oid != pOID->oid)continue;
  for(uint i = 0; i < pOID->nDataSize; i++) pBuff[i] = pOID->data[i];
  return pOID->nDataSize;
 }

 return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif //__cplusplus

#endif // OID_H_INCLUDED
