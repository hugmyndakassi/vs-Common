#ifndef ECC_SIGN_H_INCLUDED_
#define ECC_SIGN_H_INCLUDED_
#pragma once

#include "../../include/ecc/ecc_sign.h"
#include "../../include/ecc/ecc.h"
#include "../../include/ecc/ecc_verify.h"
#include "../../include/ecc/ecc_x25519.h"

#include "../../include/ecc/sha.h"
#include "../../include/ecc/base_type.h"
#include "../../include/ssl/ssl_defs.h"
#include "../../include/ssl/cipher.h"

#define edd_public_key_size  32
#define edd_secret_key_size  32
#define edd_private_key_size 64
#define edd_signature_size   64

struct NN;
struct PE_PT;
struct PA_PT;
struct Ext_PT;
struct BLINDING;
struct CIPHER;

class Sha;




/*
 * Arithmetic on twisted Edwards curve y^2 - x^2 = 1 + dx^2y^2
 * with d = -(121665/121666) mod p
 *      d = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
 *      p = 2**255 - 19
 *      p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
 * Base point: y=4/5 mod p
 *      x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
 *      y = 0x6666666666666666666666666666666666666666666666666666666666666658
 * Base point order:
 *      l = 2**252 + 27742317777372353535851937790883648493
 *      l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 */

/* Maximum number of prime p that fits into 256-bits */
const NN w_maxP{0xFFFFFFDA, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}; // 2*P < 2**256


// -- custom blind ---------------------------------------------------------
//
// edp_custom_blinding is defined in source/custom_blind.c
// source/custom_blind is created randomly on every new build
//
// -------------------------------------------------------------------------

const NN w_2d{0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A, 0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC}; // 2*d
const NN w_di{0xCDC9F843, 0x25E0F276, 0x4279542E, 0x0B5DD698, 0xCDB9CF66, 0x2B162114, 0x14D5CE43, 0x40907ED2}; // 1/d

//---------------------------------------------------------------------------------------------------
static void edp_BasePointMultiply(XY* R, const NN& sk, const BLINDING* blinding)
{
 Ext_PT S;

 if (blinding)
 {
  NN t;
  t.addr(sk, blinding->bl);
  S.BasePointMult(t, blinding->zr);
  S.AddPoint(&(blinding->BP));
 }
 else { S.BasePointMult(sk, edp_blinding.zr); }

 S.z  = S.z.inverse();
 R->x = S.x ^ S.z;
 R->y = S.y ^ S.z;
}
//---------------------------------------------------------------------------------------------------
/* Trim private key   */
static void ecp_TrimSecretKey(uint8_t* X)
{
 X[0]  &= 0xf8;
 X[31]  = (X[31] | 0x40) & 0x7f;
}


//---------------------------------------------------------------------------------------------------
static void ecp_4fold(uint8_t* Y, const uint32_t* X)
{
 int     i, j;
 uint8_t a, b;
 for (i = 32; i-- > 0; Y++)
 {
  a = 0;
  b = 0;
  for (j = 8; j > 1;)
  {
   j -= 2;
   a  = (a << 1) + ((X[j + 1] >> i) & 1);
   b  = (b << 1) + ((X[j] >> i) & 1);
  }
  Y[0]  = a;
  Y[32] = b;
 }
}
//---------------------------------------------------------------------------------------------------
static void ecp_8fold(uint8_t* Y, const uint32_t* X)
{
 int     i, j;
 uint8_t a = 0;
 for (i = 32; i-- > 0;)
 {
  for (j = 8; j-- > 0;) a = (a << 1) + ((X[j] >> i) & 1);
  *Y++ = a;
 }
}

//---------------------------------------------------------------------------------------------------
static uint8_t* ecp_EncodeKey(uint8_t* Y, const NN& X, uint8_t parity)
{
 int        i;
 const M32* m = (const M32*)X.n_;
 ;

 for (i = 0; i < 32;)
 {
  Y[i++] = m->u8.b0;
  Y[i++] = m->u8.b1;
  Y[i++] = m->u8.b2;
  Y[i++] = m->u8.b3;
  m++;
 }

 Y[31] = (Y[31] & 0x7F) | (parity << 7);
 return Y;
}
//---------------------------------------------------------------------------------------------------
static uint8_t ecp_DecodeKey(NN& Y, const uint8_t* X)
{
 int i;
 M32 m;

 for (i = 0; i < 8; i++)
 {
  m.u8.b0 = *X++;
  m.u8.b1 = *X++;
  m.u8.b2 = *X++;
  m.u8.b3 = *X++;

  Y.n_[i] = m.u32;
 }

 Y.n_[7] &= 0x7FFFFFFF;
 return (X[-1] >> 7);
}

//---------------------------------------------------------------------------------------------------
// Generate public and private key pair associated with the secret key
static void edd_CreateKeyPair(
    CIPHER&              cipher,   // Message Digest algorithm
    unsigned char*       pubKey,   // Public key out
    unsigned char*       privKey,  // Private key out
    const BLINDING*      blinding, // [optional] null or blinding context
    const unsigned char* sk)       // Secret key (32 bytes)
{
 uint8_t md[64];
 XY      Q;
 NN      t;
 CTX     ctx;

 // [a:b] = H(sk)
 cipher.Init(&ctx, cipher.pIData);
 cipher.Input(&ctx, sk, 32);
 cipher.Digest(&ctx, md);

 ecp_TrimSecretKey(md);
 t.bytesIn(md);

 edp_BasePointMultiply((XY*)&Q, t, blinding);

 ecp_EncodeKey(pubKey, Q.y, uint8_t(Q.x.n_[0] & 1));

 memcpy(privKey, sk, 32);
 memcpy(privKey + 32, pubKey, 32);
}

//---------------------------------------------------------------------------------------------------
// Generate message signature
static void edd_SignMessage(
    CIPHER&         cipher,    // Message Digest Algorithm
    uint8_t*        signature, // OUT: [64 bytes] signature (R,S)
    const uint8_t*  keyPair,   // [64 bytes] private key (sk,pk)
    const BLINDING* blinding,  // [optional] null or blinding context
    const uint8_t*  msg,       // [msg_size bytes] message to sign
    size_t          msg_size)
{
 XY      R;
 NN      a, t, r;
 uint8_t md[64];
 CTX     ctx;

 // [a:b] = H(sk)
 cipher.Init(&ctx, cipher.pIData);
 cipher.Input(&ctx, keyPair, 32);
 cipher.Digest(&ctx, md);

 ecp_TrimSecretKey(md); // a = first 32 bytes
 a.bytesIn(md);

 // r = H(b + m) mod BPO
 cipher.Init(&ctx, cipher.pIData);
 cipher.Input(&ctx, md + 32, 32);
 cipher.Input(&ctx, msg, msg_size);
 cipher.Digest(&ctx, md);

 eco_DigestToWords(r, md);
 r.reduceb(); // r mod BPO

 // R = r*P
 edp_BasePointMultiply(&R, r, blinding);
 ecp_EncodeKey(signature, R.y, uint8_t(R.x.n_[0] & 1)); // R part of signature

 // S = r + H(encoded(R) + pk + m) * a  mod BPO
 cipher.Init(&ctx, cipher.pIData);
 cipher.Input(&ctx, signature, 32);    // encoded(R)
 cipher.Input(&ctx, keyPair + 32, 32); // pk
 cipher.Input(&ctx, msg, msg_size);    // m
 cipher.Digest(&ctx, md);

 eco_DigestToWords(t, md);

 t = (t * a).reduceb(); // h()*a
 t = (t + r).reduceb();

 t.bytesOut(signature + 32); // S part of signature

 // Clear sensitive data
 a = 0;
 r = 0;
}

#endif // ECC_SIGN_H_INCLUDED_
