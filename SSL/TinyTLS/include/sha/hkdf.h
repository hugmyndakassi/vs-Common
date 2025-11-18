#ifndef HKDF_H_INCLUDED
#define HKDF_H_INCLUDED

#include "../../include/ssl/ssl_defs.h"
#include "../../include/ssl/cipher.h"
#include "hmac.h"

struct CIPHER;


class Hkdf: public HMac
{
public:
static inline const uchar Hkdf::null_[32]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

private:
    const uchar* info_;
    uint        nsize_;
    uint        bsize_;
    uint        cnt_;
public:
//---------------------------------------------------------------------------------------------------
// Based on https://tools.ietf.org/html/rfc5869
Hkdf(const CIPHER& c, const uchar* key, size_t cbKeySize, const uchar* ikm, size_t cbIkmSize) : HMac(c, (key && cbKeySize) ? key : null_, (key && cbKeySize) ? cbKeySize : c.dSize), info_(nullptr), nsize_(0), bsize_(0), cnt_(0)
{
 if (!ikm)
 {
  memcpy(this->digest_, key, cbKeySize);
  return;
 }
 hash(ikm, cbIkmSize);
 new (this) HMac(c, *this, c.dSize);
}
//---------------------------------------------------------------------------------------------------
Hkdf(const Hkdf& src, const uchar* ikm, size_t cbIkmSize) : HMac(src.c_, src, src.c_.dSize), info_(nullptr), nsize_(0), bsize_(0), cnt_(0)
{
 if (!ikm) return;
 hash(ikm, cbIkmSize);
 new (this) HMac(this->c_, *this, this->c_.dSize);
}
//---------------------------------------------------------------------------------------------------
void ExpandLabel(const char* label, const uchar* pInfo, size_t cbInfoSize, size_t L = 0)
{
 uint        i = 0, j = 0;
 uchar       labelMsg[64];
 const char* pL = label;

 // If L is 0, pInfo is hashed first and L is assumed to be digest size, else pInfo used directly.
 if (L == 0) L = j = c_.dSize;
 labelMsg[0] = uchar(L >> 8);
 labelMsg[1] = uchar(L);
 labelMsg[2] = 0x00;
 labelMsg[3] = 't';
 labelMsg[4] = 'l';
 labelMsg[5] = 's';
 labelMsg[6] = '1';
 labelMsg[7] = '3';
 labelMsg[8] = ' ';
 for (i = 9; (*label);) labelMsg[i++] = *label++;
 labelMsg[2] = (i - 3);
 if (j)
 {
  labelMsg[i++] = c_.dSize;
  c_.Hash(pInfo, cbInfoSize, &(labelMsg[i]));
  i += c_.dSize;
 }
 else
 {
  labelMsg[i++] = uchar(cbInfoSize);
  memcpy(&(labelMsg[i]), pInfo, cbInfoSize);
  i += cbInfoSize;
 }
 Expand(labelMsg, i);
}
//---------------------------------------------------------------------------------------------------
void Expand(const uchar* pInfo, size_t cbInfoSize)
{
 info_  = pInfo;
 nsize_ = cbInfoSize;
 CTX   ctx1(ctx1_);
 CTX   ctx2(ctx2_);
 uchar c[4];
 cnt_ = 0;
 c[0] = uchar(++cnt_);
 c_.Input(&ctx1, pInfo, cbInfoSize);
 c_.Input(&ctx1, c, 1);
 c_.Digest(&ctx1, digest_);
 c_.Input(&ctx2, digest_, c_.dSize);
 c_.Digest(&ctx2, digest_);
 bsize_ = c_.dSize;
}
//---------------------------------------------------------------------------------------------------
void Output(uchar* pOut, size_t cbBufSize)
{
 while (cbBufSize > 0)
 {
  while (bsize_ > 0)
  {
   *pOut++ = digest_[c_.dSize - (bsize_--)];
   if (--cbBufSize == 0) return;
  }
  CTX   ctx1(ctx1_), ctx2(ctx2_);
  uchar c[4];
  c[0] = uchar(++cnt_);
  c_.Input(&ctx1, digest_, c_.dSize);
  c_.Input(&ctx1, info_, nsize_);
  c_.Input(&ctx1, c, 1);
  c_.Digest(&ctx1, digest_);
  c_.Input(&ctx2, digest_, c_.dSize);
  c_.Digest(&ctx2, digest_);
  bsize_ += c_.dSize;
 }
}
//---------------------------------------------------------------------------------------------------
};

#endif //HKDF_H_INCLUDED
