#ifndef ECC_K256_H
#define ECC_K256_H
#pragma once

#include "ecc.h"
#include "../../include/ecc/ecc.h"
#include "../../include/ecc/ecc_k256.h"

namespace K256
{
struct ECDKeyPair
{
 XY pubKey;
 NN priKey;

void ECDKeyPair::Create(EntropyFunc fn)
{
 do {
  for (uint32_t i = 0; i < NN::N; i++) priKey.n_[i] ^= fn();
  priKey.reduce(gP256.n);
 } while (priKey.is0() || ((priKey.n_[NN::N - 1] & 0x80000000) == 0));
 pubKey = g.Mult(priKey);
}

void ECDKeyPair::Generate(const NN& nounce) { pubKey = g.Mult(priKey = nounce); }
};

struct ECDSign
{
 NN   r, s;
void ECDSign::Sign(const uint8_t digest[32], const uint8_t nounce[32], const NN& priKey)
{
 r.netIn(nounce);
 s.netIn(digest);
 s.reduce(gRN.p);
 NN k1 = r.inverse(gRN);
 r     = g.Mult(r).x;
 s     = ((r * priKey) + s).reduce(gRN);
 s     = (k1 * s).reduce(gRN);
}

bool ECDSign::Test(const uint8_t digest[32], const XY& pbKey) const
{
 const XY_PT& pubKey(*(const XY_PT*)&pbKey);
 XYZ_PT       P;
 P.x.netIn(digest).reduce(gRN.p);
 P.y = s.inverse(gRN);
 P.x = (P.x * P.y).reduce(gRN);
 NN u2((P.y * r).reduce(gRN));

 new (&P) XYZ_PT(g.Mult(P.x));
 P.Add(XYZ_PT(pubKey.Mult(u2))).Out(*(XY*)&P);

 return (P.x == r);
}

void ECDSign::OutR(uint8_t* pR) const { r.netOut(pR); }

void ECDSign::OutS(uint8_t* pS) const { s.netOut(pS); }

};
} // namespace K256


// Elliptic curve 101: https://www.johannes-bauer.com/compsci/ecc/
// Explicit formulas database: http://hyperelliptic.org/EFD/index.html
// SEC document: http://www.secg.org/SEC2-Ver-1.0.pdf
// 2.7.1 Recommended Parameters secp256k1

// The elliptic curve domain parameters over Fp associated with a Koblitz curve secp256k1 are
// specified by the sextuple T = (p; a; b; G; n; h) where the finite field F p is defined by:
//   p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
//     = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
// The curve E : y2 = x3 + ax + b over Fp is defined by:
//   a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
//   b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
// The base point G in compressed form is:
//   G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
// and in uncompressed form is:
//   G = 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
//          483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
// Finally the order n of G and the cofactor are:
//   n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
//   h = 01

// NIST SECP256k1 curve parameters.
static const EccParam gP256{{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}, {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, {0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}, {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}}, {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};


// Helper RR for modulo reduction against SECP256k1 prime.
static const struct RR gRR{{0x000003d1, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

// Helper RR for modulo reduction against SECP256k1 order.
static const struct RR gRN{{0x2fc9bec0, 0x402da173, 0x50b75fc4, 0x45512319, 0x00000001, 0x00000000, 0x00000000, 0x00000000}, {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};


namespace K256
{
struct XY_PT: XY
{
// Point Double and Add using Montgomery Ladder for constant time operation.
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
XY_PT XY_PT::Mult(const NN& m) const
{
 uint32_t     i, j, k;
 XY_PT        r;
 const XY     g1{x, y};
 const XYZ_PT gP(g1);
 XYZ_PT       R0(gP), R1(gP);

 // Search for first set bit
 j = m.lead0();
 if (j >= (NN::N << 5)) return r;
 i  = NN::N - (j >> 5) - 1;
 j &= 31;
 R1.Double();
 k = m.n_[i] << j;
 for (;;)
 {
  k <<= 1;
  if (++j >= 32)
  {
   if (i-- == 0) break;
   j = 0;
   k = m.n_[i];
  }
  XYZ_PT *p0, *p1;
  if (k & 0x80000000)
  {
   p0 = &R0;
   p1 = &R1;
  }
  else
  {
   p1 = &R0;
   p0 = &R1;
  }
  p0->Add(*p1);
  p1->Double();
 }

 R0.Out(r);
 return r;
}
};

struct XYZ_PT
{
 NN x;
 NN y;
 NN z;
 XYZ_PT() { }
// Construct a Jacobian coordinate from an [X,Y] Affine point.
 XYZ_PT(const XY& s) : x(s.x), y(s.y), z(1) { }

// Point double in Jacobian coordinate.
XYZ_PT& XYZ_PT::Double()
{
 // Point Doubling. Input : (X, Y, Z)
 //  S = 4XY^2;
 NN S((NN(4) * x).reduce(gRR));
 S = ((y * y).reduce(gRR) * S).reduce(gRR);

 // M = 3X^2 + aZ^4
 NN M((z * z).reduce(gRR));
 M = (M * M).reduce(gRR);
 M = (M * gP256.a).reduce(gRR);
 N2 M2(x * x);
 M2.reduce(gRR);
 M = ((M2.n.N0 * uint32_t(3)) += M).reduce(gRR);

 // Z' = 2YZ
 M2.n.N0 = (y * z).reduce(gRR);
 M2.n.N1 = 0;
 NN mt(M2.n.N0);
 M2 += mt;
 z   = M2.reduce(gRR);

 // X' = M^2 - 2S
 M2 = M * M;
 M2.reduce(gRR);
 NN d = gRR.p - S;
 // M2 += d; M2 += d;
 x = (M2 + d + d).reduce(gRR);

 // Y' = M(S - X') - 8Y^4
 M2.n.N0 = (y * y).reduce(gRR);
 M2.n.N0 = (M2.n.N0 * M2.n.N0).reduce(gRR);
 (M2 <<= 3).reduce(gRR);
 d  = (S >= x) ? (S - x) : S + (gRR.p - x);
 M2 = (M * d) + (gRR.p - M2.n.N0);
 y  = M2.reduce(gRR);

 return *this;
}

// Point addition in Jacobian coordinate.
XYZ_PT& XYZ_PT::Add(const XYZ_PT& q)
{
 // Point Addition
 // put : (X1, Y1, Z1), (X2, Y2, Z2)
 // U1 = X1Z2^2 U2 = X2Z1^2 S1 = Y1Z2^3 S2 = Y2Z1^3
 NN u1((q.z * q.z).reduce(gRR));
 NN u2((z * z).reduce(gRR));
 NN s1(((y * q.z).reduce(gRR) * u1).reduce(gRR));
 NN s2(((q.y * z).reduce(gRR) * u2).reduce(gRR));
 u1 = (u1 * x).reduce(gRR);
 u2 = (u2 * q.x).reduce(gRR);

 // H = U2 - U1; R = S2 - S1
 NN h((u2 >= u1) ? u2 - u1 : u2 + (gRR.p - u1));
 NN r((s2 >= s1) ? s2 - s1 : s2 + (gRR.p - s1));

 if (h.is0())
 {
  if (!r.is0()) { /*Impossible error*/ }
  return Double();
 }

 // X3 = R^2 - H^3 - 2*U1*H^2
 u2 = (h * h).reduce(gRR);
 u1 = gRR.p - (u1 * u2).reduce(gRR);
 u2 = gRR.p - (u2 * h).reduce(gRR);
 x  = ((r * r) + u2 + u1 + u1).reduce(gRR);

 // Y3 = R*(U1*H^2 - X3) - S1*H^3
 u1 = gRR.p - u1;
 if (u1 < x) u1 += gRR.p;
 u1 -= x;
 y   = ((s1 * u2) + (r * u1).reduce(gRR)).reduce(gRR);

 // Z3 = HZ1Z2
 z = (h * (z * q.z).reduce(gRR)).reduce(gRR);

 // Output : (X3, Y3, Z3)
 return *this;
}

// Convert [X,Y,Z] Jacobian coordinate back to [X,Y] Affine point.
void XYZ_PT::Out(XY& t) const
{
 NN z1(z.inverse(gRR));
 NN z2((z1 * z1).reduce(gRR));
 t.x = (x * z2).reduce(gRR);
 t.y = ((y * z2).reduce(gRR) * z1).reduce(gRR);
}
};
} // namespace K256

using K256::ECDKeyPair;
using K256::ECDSign;
using K256::XY_PT;
using K256::XYZ_PT;

static const XY_PT& g(*(const XY_PT*)&gP256.g);

#if HOW_TO_CREATE_BITCOIN_ADDRESS
// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
How to create Bitcoin      Address 0 -
    Having a private ECDSA key

    18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725 1 -
    Take the corresponding public key generated with it(33 bytes, 1 byte 0x02(y - coord is even), and 32 bytes corresponding to X coordinate)

        0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352 2 -
    Perform SHA -
    256 hashing on the public key

    0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98

#endif // HOW_TO_CREATE_BITCOIN_ADDRESS

#include <memory.h>
static void GetGrr()
{
 NN g(gP256.p);
 RR rr;

 rr.p = gP256.p;
 rr.r = NN::reverse(g);

 rr.p = gP256.n;
 rr.r = NN::reverse(rr.p);

 const uint8_t nounce[32]{0x18, 0xe1, 0x4a, 0x7b, 0x6a, 0x30, 0x7f, 0x42, 0x6a, 0x94, 0xf8, 0x11, 0x47, 0x01, 0xe7, 0xc8, 0xe7, 0x74, 0xe7, 0xf9, 0xa4, 0x7e, 0x2c, 0x20, 0x35, 0xdb, 0x29, 0xa2, 0x06, 0x32, 0x17, 0x25};
 const uint8_t c_pubKey[33]{0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e, 0x5b, 0x23, 0x52};
 uint8_t       pubKey[33];

 ECDKeyPair keyPair;
 keyPair.priKey.netIn(nounce);
 keyPair.Generate(keyPair.priKey);
 pubKey[0] = 0x02 | (0x01 & (uint8_t(keyPair.pubKey.y.n0)));
 keyPair.pubKey.x.netOut(pubKey + 1);

 int r  = 0;
 r     |= memcmp(pubKey, c_pubKey, 33);

 // nounce.netIn(priKey);

 rr.r;
}

#endif // ECC_K256_H
