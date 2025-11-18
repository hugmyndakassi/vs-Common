#ifndef ECC_X25519_H_INCLUDED_
#define ECC_X25519_H_INCLUDED_
#pragma once

#include "ecc.h"

struct CIPHER;

namespace X25519
{
//---------------------------------------------------------------------------------------------------
// Generate public and private key pair associated with the secret key
void X25519::genPubKey(
    CIPHER&        cipher, // Message Digest algorithm. Must be sha512
    uint8_t*       pubKey, // Public key out
    const uint8_t* priKey  // Private key in
// const BLINDING* blinding,   // [optional] null or blinding context
)
{
 CTX             ctx;
 uint8_t         md[64];
 const BLINDING* blinding = nullptr; // [optional] null or blinding context

 // [a:b] = H(sk)
 cipher.Init(&ctx, cipher.pIData);
 cipher.Input(&ctx, priKey, 32);
 cipher.Digest(&ctx, md);

 ecp_TrimSecretKey(md);

 XY Q;
 edp_BasePointMultiply(&Q, NN().bytesIn(md), blinding);

 ecp_EncodeKey(pubKey, Q.y, uint8_t(Q.x.n_[0] & 1));
}

struct ECDSign
{
 NN            r, s;
 const CIPHER& c_;
 ECDSign(const CIPHER& c) : c_(c) { }
//---------------------------------------------------------------------------------------------------
void X25519::ECDSign::Sign(const uint8_t* keyPair, const uint8_t* pMsg, uint32_t nSize)
{
 NN              a, z;
 CTX             ctx;
 uint8_t         md[64];
 const BLINDING* blinding = nullptr; // [optional] null or blinding context

 // [a:b] = H(sk)
 c_.Init(&ctx, c_.pIData);
 c_.Input(&ctx, keyPair, 32);
 c_.Digest(&ctx, md);

 ecp_TrimSecretKey(md); // a = first 32 bytes
 a.bytesIn(md);

 // r = H(b + m) mod BPO
 c_.Init(&ctx, c_.pIData);
 c_.Input(&ctx, md + 32, 32);
 c_.Input(&ctx, pMsg, nSize);
 c_.Digest(&ctx, md);

 eco_DigestToWords(z, md);
 z.reduceb(); // r mod BPO

 // R = r*P
 {
  XY& R(*(XY*)&ctx); // Save memory. OK to use ctx.
  edp_BasePointMultiply(&R, z, blinding);
  r     = R.y;
  r.n7 |= uint32_t(R.x.n_[0] & 1) << 31;
 }

 // S = r + H(encoded(R) + pk + m) * a  mod BPO
 c_.Init(&ctx, c_.pIData);
 c_.Input(&ctx, r, 32);            // encoded(R)
 c_.Input(&ctx, keyPair + 32, 32); // pk
 c_.Input(&ctx, pMsg, nSize);      // m
 c_.Digest(&ctx, md);

 eco_DigestToWords(s, md);

 a = (s * a).reduceb(); // h()*a
 s = (a + z).reduceb(); // r + h()*a

 // Calculated signature is stored in class member r and s.
}
//---------------------------------------------------------------------------------------------------
bool X25519::ECDSign::Test(const uint8_t* pubKey, const uint8_t* pMsg, uint32_t nSize) const
{
    EdpSigv ctx(pubKey);
    return ctx.Verify(c_, *this, pMsg, nSize);
}
void OutR(uint8_t* pR) const
{
    r.bytesOut(pR);
}

void OutS(uint8_t* pS) const
{
    s.bytesOut(pS);
}
 operator const uint8_t*() const { return (const uint8_t*)r.n_; }
};

struct G: NN
{
 static inline const BLIND edp_blinding = {{0x891D027C, 0x443AFFB7, 0x19E25BFE, 0xEA60187C, 0x969C5735, 0xDB09205D, 0xF3D36C39, 0x0EF49BB8}, {0xDAF2F8BD, 0x6BF86785, 0xBF65538F, 0x01A6BB93, 0x3ECDD092, 0x1AF401D6, 0x8AAAA6D5, 0x68C845EB}, {{0xDD128CD6, 0x901DB76E, 0x45C2C8AC, 0x24AAB8F5, 0x6BAE8649, 0xDE046039, 0x2333E3A4, 0xF55D8DAE}, {0xABA90510, 0x33E8A450, 0x35F0FE9C, 0x4D6F4DD9, 0xA27B9F2F, 0x31B6552D, 0xD5CC86FE, 0x1E76BD54}, {0xDD085A32, 0x01AE712B, 0x0284A982, 0xFE36BE10, 0x12C19914, 0x0186BCCE, 0x644E97C1, 0x973B6BC7}, {0x59A24586, 0xB794C4E1, 0xAF0A9971, 0xCAA44DC7, 0x0C3BF87A, 0x751A3235, 0xF27D8638, 0x8D01185B}}};

 G() : NN(9) { }
 G(uint32_t s) : NN(s) { }
 G(const NN& s) : NN(s) { }
 operator NN&() { return *this; }
 // Return P = P + Q, Q = 2Q
 void G::MontXY(XZ_PT& P, XZ_PT& Q) const
 {
  // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2*zb     zb=1
  // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*xb     xb=Base
  P.X.reduce();
  P.Z.reduce();
  Q.X.reduce();
  Q.Z.reduce();

  NN A;
  A.subr(P.X, P.Z); // A = x1-z1
  NN B;
  B.addr(P.X, P.Z); // B = x1+z1
  NN C;
  C.subr(Q.X, Q.Z); // C = x2-z2
  NN D;
  D.addr(Q.X, Q.Z); // D = x2+z2

  A = A ^ D; // A = (x1-z1)(x2+z2)
  B = B ^ C; // B = (x1+z1)(x2-z2)

  NN E;
  E.addr(A, B); // E = (x1-z1)(x2+z2) + (x1+z1)(x2-z2)

  B = (A >= B) ? A - B : A + (NN::P_ - B); // B = (x1-z1)(x2+z2) - (x1+z1)(x2-z2)

  P.X = E ^ E; // x3 = ((x1-z1)(x2+z2) + (x1+z1)(x2-z2))^2

  A   = B ^ B;          // A = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2
  P.Z = A ^ *(NN*)this; // z3 = ((x1-z1)(x2+z2) - (x1+z1)(x2-z2))^2*Base

  // x4 = (x2+z2)^2 * (x2-z2)^2
  // z4 = ((x2+z2)^2 - (x2-z2)^2)*((x2+z2)^2 + 121665((x2+z2)^2 - (x2-z2)^2))
  // C = (x2-z2)
  // D = (x2+z2)

  A = D ^ D; // A = (x2+z2)^2
  B = C ^ C; // B = (x2-z2)^2

  Q.X = A ^ B; // x4 = (x2+z2)^2 * (x2-z2)^2

  B = (A >= B) ? A - B : A + (NN::P_ - B); // B = (x2+z2)^2 - (x2-z2)^2
  (A += (NN(121665) ^ B)).reduce();

  Q.Z = A ^ B; // z4 = B*((x2+z2)^2 + 121665*B)
 }

 // Y = X + X
 static void G::MontX2(XZ_PT& Y, const XZ_PT& X)
 {
  //  x2 = (x+z)^2 * (x-z)^2
  //  z2 = ((x+z)^2 - (x-z)^2)*((x+z)^2 + ((A-2)/4)((x+z)^2 - (x-z)^2))

  NN A((X.X + X.Z).reduce());                            // A = (x+z)
  NN B((X.X >= X.Z) ? X.X - X.Z : X.X + (NN::P_ - X.Z)); // B = (x-z)

  A = A ^ A; // A = (x+z)^2
  B = B ^ B; // B = (x-z)^2

  Y.X = A ^ B;                               // x2 = (x+z)^2 * (x-z)^2
  B   = (A >= B) ? A - B : A + (NN::P_ - B); // B = (x+z)^2 - (x-z)^2
  (A += (NN(121665) ^ B)).reduce();          // (486662-2)/4 = 121665

  Y.Z = A ^ B; // z2 = (B)*((x+z)^2 + ((A-2)/4)(B))
 }

 // Return point Q = k*P. K in a little-endian byte array
 void G::PointMult(uint8_t* PublicKey, const NN& SecretKey) const
 {
  int             i, j, len = 8;
  uint32_t        k;
  const uint32_t* pSecret = SecretKey.n_;
  XZ_PT           P, Q, *PP[2], *QP[2];

  const G& X(*this);

  // 1: P = (2k+1)G, Q = (2k+2)G
  // 0: Q = (2k+1)G, P = (2k)G

  // Search for first non-zero bit
  while (len-- > 0)
  {
   k = pSecret[len];
   for (i = 0; i < 32; i++, k <<= 1)
    if (k & 0x80000000) break;
   if (i < 32) break;
  }
  if (len < 0)
  {
   NN(0).bytesOut(PublicKey);
   return; // No set bit found
  }

  // P = kG, Q = (k+1)G

  // First we found first non-zero bit. Should be bit 254 for keys
  // created according to the spec. Start with randomized base point

  P.Z = (X + edp_blinding.zr).reduce(); // P.Z = random
  P.X = X ^ P.Z;

  G::MontX2(Q, P);

  PP[1] = &P;
  PP[0] = &Q;
  QP[1] = &Q;
  QP[0] = &P;

  // Everything we reference in the below loop are on
  // the stack and already touched (cached)
  i++;
  k <<= 1;

  for (;;)
  {
   while (i++ < 32)
   {
    j = k >> 31;

    // Depends on bit31:
    // 1: X.MontXY(P, Q);
    // 0: X.MontXY(Q, P);
    X.MontXY(*PP[j], *QP[j]);

    k <<= 1;
   }
   if (len <= 0) break;
   i = 0;
   k = pSecret[--len];
  }

  Q.Z = P.Z.inverse();
  (P.X ^ Q.Z).bytesOut(PublicKey);
 }
};

} // namespace X25519

#endif // ECC_X25519_H_INCLUDED_
