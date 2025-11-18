#ifndef ECC_H_INCLUDED_
#define ECC_H_INCLUDED_
#pragma once

#define LITTLE_ENDIAN 1

struct N2;
struct RR;
struct XZ_PT;
struct PA_PT;
struct PE_PT;

#include "ecc_fold.hpp" // TODO: Generate (optionally)

namespace X25519
{
struct G;
}

static NN XP_ = {uint32_t(-19), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), 0x7FFFFFFF};



struct CIPHER;

typedef uint32_t (*EntropyFunc)();


typedef union U8 {
 uint64_t u8;
 struct
 {
#ifdef BIG_ENDIAN
  uint32_t high;
  uint32_t low;
#elif LITTLE_ENDIAN
  uint32_t low;
  uint32_t high;
#else
  ERROR Need to define endianness uint low;
  uint                                 high;
#endif // BIG_ENDIAN
 } u4;
} U8;


struct NN
{
 static const int N = 8;
 union {
  uint32_t n_[N];
  struct
  {
   uint32_t n0, n1, n2, n3, n4, n5, n6, n7;
  };
 };

 static inline uint32_t lead0_ = 1;
 // static NN&             P_; // !!!!
 static NN& P_ = XP_; // !!!!!!!!!!!!!!!!!!!!!!!!!

 //---------------------------------------------------------------------------------------------------
 // Initialize x25519 parameter. This is no longer needed.
 static void init(const NN& P)
 {
  P_     = P;
  lead0_ = P_.lead0();
 }
 //---------------------------------------------------------------------------------------------------
 // Calculate R that (1+R/2^256)/2^256 = 1/P. Helpful in modulo reduction.
 static NN reverse(const NN& P)
 {
  N2 PP;
  NN R;

  PP.n.N1 -= P;
  R        = PP.n.N1;
  PP      -= R * P;

  while (PP.n.N1)
  {
   NN d(PP.n.N1);
   d  += (d * R).n.N1;
   R  += d;
   PP -= d * P;
  }

  while (PP.n.N0 >= P)
  {
   R       += 1;
   PP.n.N0 -= P;
  }

  return R;
 }
 //---------------------------------------------------------------------------------------------------

 constexpr NN() : n0(0), n1(0), n2(0), n3(0), n4(0), n5(0), n6(0), n7(0) { }
 constexpr NN(uint32_t d0) : n0(d0), n1(0), n2(0), n3(0), n4(0), n5(0), n6(0), n7(0) { }
 constexpr NN(uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3, uint32_t d4, uint32_t d5, uint32_t d6, uint32_t d7) : n0(d0), n1(d1), n2(d2), n3(d3), n4(d4), n5(d5), n6(d6), n7(d7) { }
 constexpr NN(const NN& s) : n0(s.n0), n1(s.n1), n2(s.n2), n3(s.n3), n4(s.n4), n5(s.n5), n6(s.n6), n7(s.n7) { }

 //---------------------------------------------------------------------------------------------------
 // Number of leading 0 bits.
 uint32_t lead0() const
 {
  for (uint32_t i = N; i-- > 0;)
  {
   for (uint32_t j = 32; j-- > 0;)
    if ((1 << j) & n_[i]) return ((N - i) << 5) - j - 1;
  }
  return N << 5;
 }
 //---------------------------------------------------------------------------------------------------
 // Input bytes in native endianness.
 NN& bytesIn(const uint8_t* pBytes)
 {
  for (uint32_t i = 0; i < N; i++) n_[i] = reinterpret_cast<const uint32_t*>(pBytes)[i];
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Output bytes in native endianness.
 void bytesOut(uint8_t* pBytes) const
 {
  for (uint32_t i = 0; i < N; i++) reinterpret_cast<uint32_t*>(pBytes)[i] = n_[i];
 }
 //---------------------------------------------------------------------------------------------------
 // Input from network order, or big endian.
 NN& netIn(const uint8_t* pBytes)
 {
  uint32_t d = 0;
  for (uint32_t i = N; i-- > 0;)
  {
   d       = *pBytes++;
   d     <<= 8;
   d      |= *pBytes++;
   d     <<= 8;
   d      |= *pBytes++;
   d     <<= 8;
   d      |= *pBytes++;
   n_[i]   = d;
  }
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Output to network order, or big endian.
 void netOut(uint8_t* pBytes) const
 {
  for (uint32_t i = N; i-- > 0;)
  {
   uint32_t d = n_[i];
   *pBytes++  = uint8_t(d >> 24);
   *pBytes++  = uint8_t(d >> 16);
   *pBytes++  = uint8_t(d >> 8);
   *pBytes++  = uint8_t(d);
  }
 }

 //---------------------------------------------------------------------------------------------------
 // Modulo reduction by X25519 prime.
 NN& reduce()
 {
  while (*this >= NN::P_)
  {
   n_[N - 1] -= 0x80000000;
   if ((n_[0] += 19) >= 19) continue;
   for (uint32_t i = 1; ++n_[i] == 0;)
    if (++i >= N) break;
  }
  return *this;
 }
 const NN ecc_BPO{0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0, 0, 0, 0x10000000}; // X25519 BPO
 //---------------------------------------------------------------------------------------------------
 // Modulo reduce by x25519 base point order
 NN& reduceb()
 {
  NN r(ecc_BPO * (n_[N - 1] >> 28));
  if (r > *this) *this += ecc_BPO;
  *this -= r;
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Generic modulo reduction.
 NN& reduce(const NN& p)
 {
  while (*this >= p) *this -= p;
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Generic modulo inverse by prime RR.p. RR is a modulo reduction helper.
 NN inverse(const RR& r) const
 {
  NN x1(*this), x2(r.p - x1);
  NN r1(1), r2(r.p - r1);

  for (;;)
  {
   uint32_t b1 = x1.lead0(), b2 = x2.lead0();
   if ((b1 | b2) & (N << 5)) break; // x1 or x2 is 0.
   if (x2 > x1)
   {
    if (b1 - b2 > 1)
    {
     NN x3 = x1 << (b1 - b2 - 1);
     NN r3 = (r1 * (NN(1) << (b1 - b2 - 1))).reduce(r);
     while (x2 > x3)
     {
      x2 -= x3;
      if (r2 >= r3) r2 -= r3;
      else r2 += r.p - r3;
     }
    }
    else
    {
     while (x2 > x1)
     {
      x2 -= x1;
      if (r2 >= r1) r2 -= r1;
      else r2 += r.p - r1;
     }
    }
    if (x2.is1()) return r2;
   }
   else
   {
    if (b2 - b1 > 1)
    {
     NN x3 = x2 << (b2 - b1 - 1);
     NN r3 = (r2 * (NN(1) << (b2 - b1 - 1))).reduce(r);
     while (x1 > x3)
     {
      x1 -= x3;
      if (r1 >= r3) r1 -= r3;
      else r1 += r.p - r3;
     }
    }
    else
    {
     while (x1 > x2)
     {
      x1 -= x2;
      if (r1 >= r2) r1 -= r2;
      else r1 += r.p - r2;
     }
    }
    if (x1.is1()) return r1;
   }
  }
  // Error. Impossible.
  return NN();
 }
 //---------------------------------------------------------------------------------------------------
 // Modulo inverse by modulo of x25519 prime.
 NN inverse() const
 {
  NN x1(*this), x2(NN::P_ - x1);
  NN r1(1), r2(NN::P_ - r1);

  for (;;)
  {
   uint32_t b1 = x1.lead0(), b2 = x2.lead0();
   if ((b1 | b2) & (N << 5)) break; // x1 or x2 is 0.
   if (x2 > x1)
   {
    if (b1 - b2 > 1)
    {
     NN x3 = x1 << (b1 - b2 - 1);
     NN r3 = r1 ^ (NN)(NN(1) << (b1 - b2 - 1));
     while (x2 > x3)
     {
      x2 -= x3;
      if (r2 >= r3) r2 -= r3;
      else r2 += NN::P_ - r3;
     }
    }
    else
    {
     while (x2 > x1)
     {
      x2 -= x1;
      if (r2 >= r1) r2 -= r1;
      else r2 += NN::P_ - r1;
     }
    }
    if (x2.is1()) return r2;
   }
   else
   {
    if (b2 - b1 > 1)
    {
     NN x3 = x2 << (b2 - b1 - 1);
     NN r3 = r2 ^ (NN)(NN(1) << (b2 - b1 - 1));
     while (x1 > x3)
     {
      x1 -= x3;
      if (r1 >= r3) r1 -= r3;
      else r1 += NN::P_ - r3;
     }
    }
    else
    {
     while (x1 > x2)
     {
      x1 -= x2;
      if (r1 >= r2) r1 -= r2;
      else r1 += NN::P_ - r2;
     }
    }
    if (x1.is1()) return r1;
   }
  }
  // Error. Impossible.
  return NN();
 }
 //---------------------------------------------------------------------------------------------------
 // Modulo inverse of modulo by x25519 base point order.
 NN inverseb() const
 {
  const NN& P(ecc_BPO);
  NN        x1(*this);
  x1.reduceb();
  NN x2(P - x1);
  NN r1(1), r2(P - r1);

  for (;;)
  {
   uint32_t b1 = x1.lead0(), b2 = x2.lead0();
   if ((b1 | b2) & (N << 5)) break; // x1 or x2 is 0.
   if (x2 > x1)
   {
    if (b1 - b2 > 1)
    {
     NN x3 = x1 << (b1 - b2 - 1);
     NN r3 = (r1 * (NN(1) << (b1 - b2 - 1))).reduceb();
     while (x2 > x3)
     {
      x2 -= x3;
      if (r2 >= r3) r2 -= r3;
      else r2 += P - r3;
     }
    }
    else
    {
     while (x2 > x1)
     {
      x2 -= x1;
      if (r2 >= r1) r2 -= r1;
      else r2 += P - r1;
     }
    }
    if (x2.is1()) return r2;
   }
   else
   {
    if (b2 - b1 > 1)
    {
     NN x3 = x2 << (b2 - b1 - 1);
     NN r3 = (r2 * (NN(1) << (b2 - b1 - 1))).reduceb();
     while (x1 > x3)
     {
      x1 -= x3;
      if (r1 >= r3) r1 -= r3;
      else r1 += P - r3;
     }
    }
    else
    {
     while (x1 > x2)
     {
      x1 -= x2;
      if (r1 >= r2) r1 -= r2;
      else r1 += P - r2;
     }
    }
    if (x1.is1()) return r1;
   }
  }
  // Error. Impossible.
  return NN();
 }
 //---------------------------------------------------------------------------------------------------
 // Y = X ** E mod P. E is in little-endian format
 void EMod(NN& Y, const NN& E) const
 {
  Y = 1;
  for (uint32_t bytes = N; bytes-- > 0;)
  {
   uint32_t e = E.n_[bytes];
   for (uint32_t i = 0; i < 32; i++)
   {
    Y = Y ^ Y;
    if (e & 0x80000000) Y = Y ^ *this;
    e <<= 1;
   }
  }
  Y.reduce();
 }
 //---------------------------------------------------------------------------------------------------

 operator X25519::G&() { return *((X25519::G*)this); } // ???????????????????

 //---------------------------------------------------------------------------------------------------
 NN operator+(const NN& m) const
 {
  NN r(*this);
  for (uint32_t i = 0; i < N; i++)
  {
   if ((r.n_[i] += m.n_[i]) >= m.n_[i]) continue;
   for (uint32_t j = i + 1; j < N; j++)
    if (++r.n_[j]) break;
  }

  return r;
 }
 //---------------------------------------------------------------------------------------------------
 NN operator-(const NN& m) const
 {
  NN r(*this);
  for (uint32_t i = 0; i < N; i++)
  {
   if (r.n_[i] >= m.n_[i])
   {
    r.n_[i] -= m.n_[i];
    continue;
   }
   r.n_[i] -= m.n_[i];
   for (uint32_t j = i + 1; j < N; j++)
    if (r.n_[j]--) break;
  }

  return r;
 }
 //---------------------------------------------------------------------------------------------------
 NN operator<<(uint32_t w) const
 {
  int32_t i = N, j = i - (w >> 5), d1 = w & 31, d2 = 32 - d1;
  NN      r;
  if (d1 == 0)
  {
   while (j-- > 0) r.n_[--i] = n_[j];
   while (i-- > 0) r.n_[i] = 0;
   return r;
  }
  j--;
  while (j > 0)
  {
   r.n_[--i]  = n_[j--] << d1;
   r.n_[i]   |= n_[j] >> d2;
  }
  r.n_[--i] = n_[j] << d1;
  while (i > 0) r.n_[--i] = 0;

  return r;
 }
 //---------------------------------------------------------------------------------------------------
 NN operator>>(uint32_t w) const
 {
  int32_t i = 0, j = i + (w >> 5), d1 = w & 31, d2 = 32 - d1;
  NN      r;
  if (d1 == 0)
  {
   while (j < N) r.n_[i++] = n_[j++];
   while (i < N) r.n_[i++] = 0;
   return r;
  }
  while (j < N - 1)
  {
   r.n_[i]    = n_[j] >> d1;
   r.n_[i++] |= n_[++j] << d2;
  }
  r.n_[i++] = n_[j] >> d1;
  while (i < N) r.n_[i++] = 0;

  return r;
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator+=(const NN& m)
 {
  for (uint32_t i = 0; i < N; i++)
  {
   if ((n_[i] += m.n_[i]) >= m.n_[i]) continue;
   for (uint32_t j = i + 1; j < N; j++)
    if (++n_[j]) break;
  }

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator-=(const NN& m)
 {
  for (uint32_t i = 0; i < N; i++)
  {
   if (n_[i] >= m.n_[i])
   {
    n_[i] -= m.n_[i];
    continue;
   }
   n_[i] -= m.n_[i];
   for (uint32_t j = i + 1; j < N; j++)
    if (n_[j]--) break;
  }

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator+=(uint32_t w)
 {
  if ((n_[0] += w) >= w) return *this;
  for (uint32_t j = 1; j < N; j++)
   if (++n_[j]) break;

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator-=(uint32_t w)
 {
  if (n_[0] < w)
  {
   for (uint32_t j = 1; j < N; j++)
    if (n_[j]--) break;
  }
  n_[0] -= w;
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator<<=(uint32_t w)
 {
  int32_t i = N, j = i - (w >> 5), d1 = w & 31, d2 = 32 - d1;
  if (d1 == 0)
  {
   while (j-- > 0) n_[--i] = n_[j];
   while (i-- > 0) n_[i] = 0;
   return *this;
  }
  j--;
  while (j > 0)
  {
   n_[--i]  = n_[j--] << d1;
   n_[i]   |= n_[j] >> d2;
  }
  n_[--i] = n_[j] << d1;
  while (i > 0) n_[--i] = 0;

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator>>=(uint32_t w)
 {
  int32_t i = 0, j = i + (w >> 5), d1 = w & 31, d2 = 32 - d1;
  if (d1 == 0)
  {
   while (j < N) n_[i++] = n_[j++];
   while (i < N) n_[i++] = 0;
   return *this;
  }
  while (j < N - 1)
  {
   n_[i]    = n_[j] >> d1;
   n_[i++] |= n_[++j] << d2;
  }
  n_[i++] = n_[j] >> d1;
  while (i < N) n_[i++] = 0;

  return *this;
 }

 //---------------------------------------------------------------------------------------------------
 bool operator>=(const NN& t) const
 {
  for (uint32_t i = N; i-- > 0;)
  {
   if (n_[i] > t.n_[i]) return true;
   if (n_[i] < t.n_[i]) return false;
  }
  return true;
 }
 //---------------------------------------------------------------------------------------------------
 bool operator<=(const NN& t) const
 {
  for (uint32_t i = N; i-- > 0;)
  {
   if (n_[i] > t.n_[i]) return false;
   if (n_[i] < t.n_[i]) return true;
  }
  return true;
 }
 //---------------------------------------------------------------------------------------------------
 bool operator==(const NN& t) const
 {
  for (uint32_t i = 0; i < N; i++)
   if (n_[i] != t.n_[i]) return false;
  return true;
 }
 //---------------------------------------------------------------------------------------------------
 bool operator!=(const NN& t) const
 {
  for (uint32_t i = 0; i < N; i++)
   if (n_[i] != t.n_[i]) return true;
  return false;
 }
 //---------------------------------------------------------------------------------------------------
 bool operator>(const NN& t) const
 {
  for (uint32_t i = N; i-- > 0;)
  {
   if (n_[i] > t.n_[i]) return true;
   if (n_[i] < t.n_[i]) return false;
  }
  return false;
 }
 //---------------------------------------------------------------------------------------------------
 bool operator<(const NN& t) const
 {
  for (uint32_t i = N; i-- > 0;)
  {
   if (n_[i] > t.n_[i]) return false;
   if (n_[i] < t.n_[i]) return true;
  }
  return false;
 }
 //---------------------------------------------------------------------------------------------------
 bool operator<(uint32_t t) const
 {
  for (uint32_t i = N; i-- > 1;)
   if (n_[i]) return false;
  return (n0 < t);
 }
 //---------------------------------------------------------------------------------------------------
 NN& operator=(uint32_t m)
 {
  for (uint32_t i = N; i-- > 1;) n_[i] = 0;
  n0 = m;
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Simple multiplication, with multiplicant just a uint32
 N2 operator*(uint32_t m) const
 {
  uint32_t i;
  U8       oneData{0};
  N2       ret;

  for (i = 0; i < N; i++)
  {
   if ((ret.n_[i] += oneData.u4.high) < oneData.u4.high)
   {
    uint32_t k = i + 1;
    while (++ret.n_[k] == 0 && k < N2::N - 1) k++;
   }
   oneData.u8 = (uint64_t)n_[i] * m;
   if ((ret.n_[i] += oneData.u4.low) < oneData.u4.low) oneData.u4.high++;
  }
  ret.n_[i] += oneData.u4.high;

  return ret;
 }
 //---------------------------------------------------------------------------------------------------
 // Simple multiplication only. No modulo reduction.
 N2 operator*(const NN& m) const
 {
  uint32_t i, j;
  U8       oneData;
  N2       ret;

  for (i = 0; i < N; i++)
  {
   for (j = 0; j < N; j++)
   {
    oneData.u8 = (uint64_t)n_[i] * m.n_[j];
    if ((ret.n_[i + j] += oneData.u4.low) < oneData.u4.low) oneData.u4.high++;
    if ((ret.n_[i + j + 1] += oneData.u4.high) < oneData.u4.high)
    {
     uint32_t k = i + j + 2;
     while (++ret.n_[k] == 0) k++;
    }
   }
  }

  return ret;
 }
 //---------------------------------------------------------------------------------------------------
 // Multiply and modulo by x25519 prime.
 NN operator^(const NN& m) const
 {
  uint32_t i, j;
  U8       oneData;
  N2       R;

  // R = this * m
  for (i = 0; i < N; i++)
  {
   for (j = 0; j < N;)
   {
    oneData.u8 = (uint64_t)n_[i] * m.n_[j];
    if ((R.n_[i + (j++)] += oneData.u4.low) < oneData.u4.low) oneData.u4.high++;
    if ((R.n_[i + j] += oneData.u4.high) >= oneData.u4.high) continue;
    for (uint32_t k = i + j + 1; ++R.n_[k] == 0; k++) { }
   }
  }

  // Modulo reduce by P
  for (i = NN::N; i-- > 0;)
  {
   oneData.u8       = (uint64_t)R.n.N1.n_[i] * 38;
   R.n.N1.n_[i]     = 0;
   oneData.u4.high += ((R.n.N0.n_[i] += oneData.u4.low) < oneData.u4.low);
   for (j = i + 1; oneData.u4.high = ((R.n.N0.n_[j] += oneData.u4.high) < oneData.u4.high); j++);
   i += (R.n.N1.n_[i] > 0);
  }

  while (R.n.N0 >= NN::P_)
  {
   R.n.N0.n_[NN::N - 1] -= 0x80000000;
   j                     = 19;
   for (i = 0; (j = ((R.n.N0.n_[i] += j) < j)); i++);
  }

  return R.n.N0;
 }
 //---------------------------------------------------------------------------------------------------
 operator bool() const
 {
  for (uint32_t i = 0; i < N; i++)
   if (n_[i]) return true;
  return false;
 }
 //---------------------------------------------------------------------------------------------------
 bool is0() const
 {
  for (int32_t i = N; i-- > 0;)
   if (n_[i]) return false;
  return true;
 }
 //---------------------------------------------------------------------------------------------------
 bool is1() const
 {
  for (int32_t i = N; i-- > 0;)
   if (n_[i]) return ((i == 0) && n_[i] == 1);
  return false;
 }
 //---------------------------------------------------------------------------------------------------

 operator uint8_t*() const { return (uint8_t*)n_; }

 //---------------------------------------------------------------------------------------------------
 // Sub then modulo reduction by x25519 prime.
 NN& subr(const NN& a, const NN& b)
 {
  *this = a;
  if (a < b) *this += P_;
  *this -= b;
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Add then modulo reduction by x25519 prime.
 NN& addr(const NN& a, const NN& b)
 {
  *this  = a;
  *this += b;
  this->reduce();
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 static NN& NNGetPP(void) { return XP_; }

 // static NN& NNGetP(void)
 //{
 //  static NN P_{uint32_t(-19), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), 0x7FFFFFFF };
 //  return P_;
 // }
};
//===================================================================================================
struct N2
{
 static const int N = NN::N << 1;

 static inline NN P_{uint32_t(-38), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1), uint32_t(-1)};
 static inline NN R_{38, 0, 0, 0, 0, 0, 0, 0};

 union {
  uint32_t n_[N];
  struct
  {
   NN N0, N1;
  } n;
 };

 //---------------------------------------------------------------------------------------------------
 // Initialize x25519 parameters. P is the x25519 prime.
 static void init(const NN& P)
 {
  NN::init(P);

  P_   = P;
  P_ <<= P_.lead0();
  R_   = NN::reverse(P_);
 }
 //---------------------------------------------------------------------------------------------------
 N2() : n{0, 0} { }
 //---------------------------------------------------------------------------------------------------
 N2(const NN& n1, uint32_t n0) : n{n0, n1} { }
 //---------------------------------------------------------------------------------------------------
 N2(const N2& s) : n(s.n) { }
 //---------------------------------------------------------------------------------------------------
 // Modulo reduction by X25519 prime.
 NN& reduce()
 {
  uint32_t i, j;
  U8       oneData{0};
  for (i = 0; i < NN::N;)
  {
   oneData.u8  = (uint64_t)n.N1.n_[i] * 38;
   n.N1.n_[i]  = 0;
   n.N0.n_[i] += oneData.u4.low;
   if (n.N0.n_[i++] < oneData.u4.low) oneData.u4.high++;
   n.N0.n_[i] += oneData.u4.high;
   if (n.N0.n_[i] >= oneData.u4.high) continue;
   for (j = i + 1; ++n.N0.n_[j] == 0; j++) { }
  }
  oneData.u4.high = n.N1.n_[0];
  n.N1.n_[0]      = 0;
  while (oneData.u4.high)
  {
   oneData.u4.low = oneData.u4.high * 38;
   if ((n.N0.n_[0] += oneData.u4.low) < oneData.u4.low)
   {
    for (uint32_t k = 1; ++n.N0.n_[k] == 0; k++) { }
   }
   oneData.u4.high = n.N1.n_[0];
   n.N1.n_[0]      = 0;
  }
  while (n.N0 >= NN::P_)
  {
   n.N0.n_[NN::N - 1] -= 0x80000000;
   if ((n.N0.n_[0] += 19) >= 19) continue;
   for (j = 1; ++n.N0.n_[j] == 0;)
    if (++j >= NN::N) break;
  }

  return n.N0;
 }
 //---------------------------------------------------------------------------------------------------
 // Modulo reduction by x25519 base point order.
 N2& reduceb()
 {
  static const NN bpr{0xcf5d3ed0, 0x812631a5, 0x2f79cd65, 0x4def9dea, 1, 0, 0, 0};
  NN              bpo(ecc_BPO);
  bpo <<= bpo.lead0();
  N2 d(n.N1, 0);
  d      -= d.n.N1 * bpr;
  d.n.N0  = 0;
  d      += d.n.N1 * bpr;
  *this  -= d;

  while (n.N1)
  {
   if (n.N0 < bpo) n.N1 -= 1;
   n.N0 -= bpo;
  }

  n.N0.reduceb();
  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 // Generic reduction with a helper RR.
 NN& reduce(const RR& r)
 {
  NN n1(n.N1);
  *this -= n1 * r.p;
  n1     = (n1 * r.r).n.N1;
  *this -= (n1 * r.p);
  while (n.N1)
  {
   if (n.N0 < r.p) n.N1 -= 1;
   n.N0 -= r.p;
  }
  while (n.N0 >= r.p) n.N0 -= r.p;
  return n.N0;
 }
 //---------------------------------------------------------------------------------------------------

 operator NN() { return n.N0; }

 //---------------------------------------------------------------------------------------------------
 bool operator==(const N2& m) const { return ((n.N0 == m.n.N0) && (n.N1 == m.n.N1)); }
 //---------------------------------------------------------------------------------------------------
 N2& operator=(const N2& s)
 {
  n.N0 = s.n.N0;
  n.N1 = s.n.N1;
  return (*this);
 }
 //---------------------------------------------------------------------------------------------------
 N2 operator+(const N2& m) const
 {
  N2 r(*this);
  for (uint32_t i = 0; i < N; i++)
  {
   if ((r.n_[i] += m.n_[i]) >= m.n_[i]) continue;
   for (uint32_t j = i + 1; j < N; j++)
    if (++r.n_[j]) break;
  }

  return r;
 }
 //---------------------------------------------------------------------------------------------------
 N2 operator+(const NN& m) const
 {
  N2 r(*this);
  for (uint32_t i = 0; i < NN::N; i++)
  {
   if ((r.n_[i] += m.n_[i]) >= m.n_[i]) continue;
   for (uint32_t j = i + 1; j < N; j++)
    if (++r.n_[j]) break;
  }

  return r;
 }
 //---------------------------------------------------------------------------------------------------
 N2& operator+=(const NN& m)
 {
  for (uint32_t i = 0; i < NN::N; i++)
  {
   if ((n_[i] += m.n_[i]) >= m.n_[i]) continue;
   for (uint32_t j = i + 1; j < N; j++)
    if (++n_[j]) break;
  }

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 N2& operator+=(const N2& m)
 {
  for (uint32_t i = 0; i < N; i++)
  {
   if ((n_[i] += m.n_[i]) >= m.n_[i]) continue;
   for (uint32_t j = i + 1; j < N; j++)
    if (++n_[j]) break;
  }

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 N2& operator-=(const N2& m)
 {
  for (uint32_t i = 0; i < N; i++)
  {
   if (n_[i] >= m.n_[i])
   {
    n_[i] -= m.n_[i];
    continue;
   }
   n_[i] -= m.n_[i];
   for (uint32_t j = i + 1; j < N; j++)
    if (n_[j]--) break;
  }

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 N2& operator<<=(uint32_t w)
 {
  int32_t i = N, j = i - (w >> 5), d1 = w & 31, d2 = 32 - d1;
  if (d1 == 0)
  {
   while (j-- > 0) n_[--i] = n_[j];
   while (i-- > 0) n_[i] = 0;
   return *this;
  }
  j--;
  while (j > 0)
  {
   n_[--i]  = n_[j--] << d1;
   n_[i]   |= n_[j] >> d2;
  }
  n_[--i] = n_[j] << d1;
  while (i > 0) n_[--i] = 0;

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 N2& operator>>=(uint32_t w)
 {
  int32_t i = 0, j = i + (w >> 5), d1 = w & 31, d2 = 32 - d1;
  if (d1 == 0)
  {
   while (j < N) n_[i++] = n_[j++];
   while (i < N) n_[i++] = 0;
   return *this;
  }
  while (j < N - 1)
  {
   n_[i]    = n_[j] >> d1;
   n_[i++] |= n_[++j] << d2;
  }
  n_[i++] = n_[j] >> d1;
  while (i < N) n_[i++] = 0;

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
};
//===================================================================================================
// Helper for modulo reduction
struct RR
{
 NN r; // (1+(r/2^256))/2^256 == 1/P
 NN p; // The prime
};
//===================================================================================================
// Projective coordinates
struct Ext_PT
{
 NN x; // x/z
 NN y; // y/z
 NN z;
 NN t; // xy/z
 public:
 //---------------------------------------------------------------------------------------------------
 // Reference: http://eprint.iacr.org/2008/522
 // Cost: 7M + 7add
 // Return: R = P + BasePoint
 void Ext_PT::AddBasePoint()
 {
  x.reduce();
  y.reduce();
  z.reduce();
  t.reduce();

  NN a;
  a.subr(y, x); // A = (Y1-X1)*(Y2-X2)
  a = a ^ gPreFold[1].YmX;

  NN b;
  b.addr(y, x); // B = (Y1+X1)*(Y2+X2)
  b = b ^ gPreFold[1].YpX;

  NN c(t ^ gPreFold[1].T2d); // C = T1*2d*T2
  NN d((z + z).reduce());    // D = 2*Z1
  NN e;
  e.subr(b, a); // E = B-A

  (b += a).reduce(); // H = B+A
  a.subr(d, c);      // F = D-C
  (d += c).reduce(); // G = D+C

  x = e ^ a; // E*F
  y = b ^ d; // H*G
  t = e ^ b; // E*H
  z = d ^ a; // G*F
 }
 //---------------------------------------------------------------------------------------------------
 // Assumptions: pre-computed q. Cost: 8M + 6add. Return: P = P + Q
 void Ext_PT::AddPoint(const PE_PT* q)
 {
  NN a; // A = (Y1-X1)*(Y2-X2)
  a.subr(y, x);
  a = a ^ q->YmX;

  NN b; // B = (Y1+X1)*(Y2+X2)
  b.addr(y, x);
  b = b ^ q->YpX;

  NN c(t ^ q->T2d); // C = T1*2d*T2
  NN d(z ^ q->Z2);  // D = Z1*2*Z2
  NN e;
  e.subr(b, a); // E = B-A

  (b += a).reduce(); // H = B+A
  a.subr(d, c);      // F = D-C
  (d += c).reduce(); // G = D+C

  x = e ^ a; // E*F
  y = b ^ d; // H*G
  t = e ^ b; // E*H
  z = d ^ a; // G*F
 }
 //---------------------------------------------------------------------------------------------------
 // Reference: http://eprint.iacr.org/2008/522 Cost: 4M + 4S + 7add
 // Return: P = 2*P
 void Ext_PT::DoublePoint()
 {
  x.reduce();
  y.reduce();
  z.reduce();
  t.reduce();

  NN a(x ^ x); // A = X1^2
  NN b(y ^ y); // B = Y1^2
  NN c(z ^ z); // C = 2*Z1^2

  c = (c + c).reduce();

  NN d(w_maxP);
  d.reduce(); // D = -A
  d = (d >= a) ? d - a : d + (NN::P_ - a);
  a.subr(d, b);      // H = D-B
  (d += b).reduce(); // G = D+B
  b.subr(d, c);      // F = G-C

  NN e((x + y).reduce()); // E = (X1+Y1)^2-A-B = (X1+Y1)^2+H

  e = e ^ e;
  (e += a).reduce();

  x = e ^ b; // E*F
  y = a ^ d; // H*G
  z = d ^ b; // G*F
  t = e ^ a; // E*H
 }
 //---------------------------------------------------------------------------------------------------
 // Assumptions: pre-computed q, q->Z=1. Cost: 7M + 7add
 // Return: P = P + Q
 void Ext_PT::AddAffinePoint(const PA_PT* q)
 {
  y.reduce();
  x.reduce();
  z.reduce();

  NN a;
  a.subr(y, x); // A = (Y1-X1)*(Y2-X2)
  a = a ^ q->YmX;

  NN b;
  b.addr(y, x); // B = (Y1+X1)*(Y2+X2)
  b = b ^ q->YpX;

  NN c(t ^ q->T2d); // C = T1*2d*T2
  NN d;
  d.addr(z, z); // D = Z1*2*Z2 (Z2=1)
  NN e;
  e.subr(b, a); // E = B-A

  (b += a).reduce(); // H = B+A
  a.subr(d, c);      // F = D-C
  (d += c).reduce(); // G = D+C

  x = e ^ a; // E*F
  y = b ^ d; // H*G
  t = e ^ b; // E*H
  z = d ^ a; // G*F
 }
 //---------------------------------------------------------------------------------------------------
 /* -- FOLDING ---------------------------------------------------------------
 //
 //    The performance boost is achieved by a process that I call FOLDING.
 //    Folding can be viewed as an extension of Shamir's trick but it is based
 //    on break down of the scalar multiplier of a*P into a polynomial of the
 //    form:
 //
 //        a*P = SUM(a_i*2^(i*w))*P    for i = 0,1,2,...n-1
 //
 //        a*P = SUM(a_i*P_i)
 //
 //        where P_i = (2^(i*w))*P
 //              n = number of folds
 //              w = bit-length of a_i
 //
 //    For folding of 8, 256-bit multiplier 'a' is chopped into 8 limbs of
 //    32-bits each (a_0, a_1,...a_7). P_0 - P_7 can be pre-calculated and
 //    their 256-different permutations can be cached or hard-coded
 //    directly into the code.
 //    This arrangement combined with double-and-add approach reduces the
 //    number of EC point calculations by a factor of 8. We only need 31
 //    double & add operations.
 //
 //       +---+---+---+---+---+---+- .... -+---+---+---+---+---+---+
 //  a = (|255|254|253|252|251|250|        | 5 | 4 | 3 | 2 | 1 | 0 |)
 //       +---+---+---+---+---+---+- .... -+---+---+---+---+---+---+
 //
 //                     a_i                       P_i
 //       +---+---+---+ .... -+---+---+---+    ----------
 // a7 = (|255|254|253|       |226|225|224|) * (2**224)*P
 //       +---+---+---+ .... -+---+---+---+
 // a6 = (|225|224|223|       |194|193|192|) * (2**192)*P
 //       +---+---+---+ .... -+---+---+---+
 // a5 = (|191|190|189|       |162|161|160|) * (2**160)*P
 //       +---+---+---+ .... -+---+---+---+
 // a4 = (|159|158|157|       |130|129|128|) * (2**128)*P
 //       +---+---+---+ .... -+---+---+---+
 // a3 = (|127|126|125|       | 98| 97| 96|) * (2**96)*P
 //       +---+---+---+ .... -+---+---+---+
 // a2 = (| 95| 94| 93|       | 66| 65| 64|) * (2**64)*P
 //       +---+---+---+ .... -+---+---+---+
 // a1 = (| 63| 62| 61|       | 34| 33| 32|) * (2**32)*P
 //       +---+---+---+ .... -+---+---+---+
 // a0 = (| 31| 30| 29|       | 2 | 1 | 0 |) * (2**0)*P
 //       +---+---+---+ .... -+---+---+---+
 //         |   |                   |   |
 //         |   +--+                |   +--+
 //         |      |                |      |
 //         V      V     slices     V      V
 //       +---+  +---+    ....    +---+  +---+
 //       |255|  |254|            |225|  |224|   P7
 //       +---+  +---+    ....    +---+  +---+
 //       |225|  |224|            |193|  |192|   P6
 //       +---+  +---+    ....    +---+  +---+
 //       |191|  |190|            |161|  |160|   P5
 //       +---+  +---+    ....    +---+  +---+
 //       |159|  |158|            |129|  |128|   P4
 //       +---+  +---+    ....    +---+  +---+
 //       |127|  |126|            | 97|  | 96|   P3
 //       +---+  +---+    ....    +---+  +---+
 //       | 95|  | 94|            | 65|  | 64|   P2
 //       +---+  +---+    ....    +---+  +---+
 //       | 63|  | 62|            | 33|  | 32|   P1
 //       +---+  +---+    ....    +---+  +---+
 //       | 31|  | 30|            | 1 |  | 0 |   P0
 //       +---+  +---+    ....    +---+  +---+
 // cut[]:  0      1      ....      30     31
 // --------------------------------------------------------------------------
 // Return S = a*P where P is ed25519 base point and R is random
 */
 void Ext_PT::BasePointMult(const NN& sk, const NN& r)
 {
  int     i = 1;
  uint8_t cut[32];

  ecp_8fold(cut, sk.n_);

  const PA_PT* P0 = &(gPreFold[cut[0]]);

  NN rR(r);
  rR.reduce();

  x.subr(P0->YpX, P0->YmX); // 2x
  y.addr(P0->YpX, P0->YmX); // 2y
  t = P0->T2d ^ w_di;       // 2xy

  // Randomize starting point
  z.addr(rR, rR); // Z = 2R
  x = x ^ rR;     // X = 2xR
  t = t ^ rR;     // T = 2xyR
  y = y ^ rR;     // Y = 2yR

  do {
   DoublePoint();
   AddAffinePoint(&gPreFold[cut[i]]);
  } while (i++ < 31);
 }
};
//===================================================================================================
// Affine coordinates
struct XY
{
 NN   x;
 NN   y;
 bool operator==(const XY& t) const { return ((x == t.x) && (y == t.y)); }
};
//===================================================================================================
struct XZ_PT
{
 NN X; // x = X/Z
 NN Z;
};
//===================================================================================================
// pre-computed, extended point
struct PE_PT
{
 NN YpX; // Y+X
 NN YmX; // Y-X
 NN T2d; // 2d*T
 NN Z2;  // 2*Z
 public:
 //---------------------------------------------------------------------------------------------------
 void fromExtPT(const Ext_PT& p)
 {
  NN x(p.x), y(p.y), z(p.z);
  x.reduce();
  y.reduce();
  z.reduce();

  YpX.addr(y, x);
  YmX.subr(y, x);
  T2d = p.t ^ w_2d;
  Z2  = (z + z).reduce();
 }
};
//===================================================================================================
// pre-computed, Affine point
struct PA_PT
{
 NN YpX; // Y+X
 NN YmX; // Y-X
 NN T2d; // 2d*T
};
//===================================================================================================
struct BLIND
{
 NN    bl;
 NN    zr;
 PE_PT BP;
};

struct BLINDING: BLIND
{


 //---------------------------------------------------------------------------------------------------
 // -- Blinding -------------------------------------------------------------
 //
 //  Blinding is a measure to protect against side channel attacks.
 //  Blinding randomizes the scalar multiplier.
 //
 //  Instead of calculating a*P, calculate (a+b mod BPO)*P + B
 //
 //  Where b = random blinding and B = -b*P
 //
 // -------------------------------------------------------------------------
 BLINDING::BLINDING(
     CIPHER&        cipher, // Message Digest Context
     const uint8_t* seed,   // Random blinding seed
     uint32_t       cbSize  // size of blinding seed
 )
 {
  struct
  {
   Ext_PT  T;
   NN      t;
   uint8_t digest[64];
  } d;

  CTX ctx;

  // Use edp_custom_blinding to protect generation of the new blinder
  cipher.Init(&ctx, cipher.pIData);
  cipher.Input(&ctx, (const uint8_t*)edp_blinding.zr.n_, 32);
  cipher.Input(&ctx, seed, cbSize);
  cipher.Digest(&ctx, d.digest);

  zr.bytesIn(d.digest + 32);
  d.t.bytesIn(d.digest);
  d.t.reduceb();
  bl = ecc_BPO - d.t;

  (d.t += edp_blinding.bl).reduceb();
  d.T.BasePointMult(d.t, edp_blinding.zr);
  d.T.AddPoint(&edp_blinding.BP);

  BP.fromExtPT(d.T);

  // clear potentially sensitive data
  memset(&d, 0, sizeof(d));
 }
};
//===================================================================================================
// ECC curve parameters.
struct EccParam
{
 NN p; // The prime
 NN a; // ECC parameter a
 NN b; // ECC parameter b
 XY g; // Generator point
 NN n; // Order of generator point.
};
//===================================================================================================
extern const NN    w_di;
extern const NN    ecc_BPO;
extern const BLIND edp_blinding;
extern const PA_PT gPreFold[256];

#endif // ECC_H_INCLUDED_
