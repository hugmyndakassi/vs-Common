#ifndef HMAC1_H_INCLUDED
#define HMAC1_H_INCLUDED

#include "../../include/ssl/ssl_defs.h"
#include "../../include/sha/hmac.h"

#include "../../include/ssl/cipher.h"

struct CIPHER;

class HMac
{
 protected:
 const CIPHER& c_;
 CTX           ctx1_;
 CTX           ctx2_;
 uchar         digest_[32];

 //---------------------------------------------------------------------------------------------------
 public:
 operator const uchar*() const { return digest_; }
 uint size() const { return c_.dSize; }
 //---------------------------------------------------------------------------------------------------
 HMac(const CIPHER& c, const uchar* key, size_t cbKeySize) : c_(c)
 {
  size_t i = 0;
  uchar  ipad[64], opad[64];
  for (i = 0; i < cbKeySize; i++)
  {
   ipad[i] = key[i] ^ 0x36;
   opad[i] = key[i] ^ 0x5C;
  }
  for (; i < 64; i++)
  {
   ipad[i] = 0x36;
   opad[i] = 0x5C;
  }
  c_.Init(&ctx1_, c_.pIData);
  c_.Init(&ctx2_, c_.pIData);
  c_.Input(&ctx1_, ipad, sizeof(ipad));
  c_.Input(&ctx2_, opad, sizeof(opad));
 }
 //---------------------------------------------------------------------------------------------------
 HMac& hash(HMac& src, const uchar* text, size_t cbSize)
 {
  CTX   ctx1(ctx1_);
  CTX   ctx2(ctx2_);
  uchar d[32];
  c_.Input(&ctx1, src, c_.dSize);
  c_.Input(&ctx1, text, cbSize);
  c_.Digest(&ctx1, d);
  c_.Input(&ctx2, d, c_.dSize);
  c_.Digest(&ctx2, digest_);

  return *this;
 }
 //---------------------------------------------------------------------------------------------------
 HMac& hash(const uchar* text, size_t cbSize)
 {
  CTX   ctx1(ctx1_);
  CTX   ctx2(ctx2_);
  uchar d[32];
  c_.Input(&ctx1, text, cbSize);
  c_.Digest(&ctx1, d);
  c_.Input(&ctx2, d, c_.dSize);
  c_.Digest(&ctx2, digest_);

  return *this;
 }
};
//===================================================================================================
class PrfHash
{
 const uchar* seed_;
 uint         nSeedSize_;
 uint         nGenSize_;
 uint         nUseSize_;
 HMac         mac_;
 HMac         a_;

 //---------------------------------------------------------------------------------------------------
 public:
 PrfHash(const CIPHER& c, const uchar* key, size_t cbKeySize, const uchar* seed, size_t cbSeedSize) : seed_(seed), nSeedSize_(cbSeedSize), nGenSize_(0), nUseSize_(0), mac_(c, key, cbKeySize), a_(c, key, cbKeySize) { a_.hash(seed_, nSeedSize_); }
 //---------------------------------------------------------------------------------------------------
 void Output(uchar* pOut, size_t cbBufSize)
 {
  while (cbBufSize > 0)
  {
   int nAvail(nGenSize_ - nUseSize_);
   if (nAvail <= 0)
   {
    // Generate one round of 32 bytes.
    mac_.hash(a_, seed_, nSeedSize_);
    // Generate A[i+1] = HMAC_hash(key, A[i])
    a_.hash(a_, a_.size());
    nGenSize_ += mac_.size();
    continue;
   }
   // Then take any bytes that are available.
   if (nAvail > int(cbBufSize)) nAvail = int(cbBufSize);
   int i, off = nUseSize_ & 31;
   for (i = 0; i < nAvail; i++) pOut[i] = mac_[i + off];
   nUseSize_ += nAvail;
   pOut      += nAvail;
   cbBufSize -= nAvail;
  }
 }
 //---------------------------------------------------------------------------------------------------
};
//===================================================================================================
#endif // HMAC1_H_INCLUDED
