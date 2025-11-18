#ifndef _SHA_H_INCLUDED_03_12_2019_
#define _SHA_H_INCLUDED_03_12_2019_

#include "../../include/ssl/cipher.h"
#include "../../include/ssl/ssl_defs.h"

// #define DO_TEST_SSA

struct CIPHER;

//---------------------------------------------------------------------------------------------------
void SsaSign(const CIPHER& sha, uint8_t* block, uint32_t nSize, const uint8_t* pCtx, uint32_t nCtxLen)
{
 uint8_t cnt[8]{0, 0, 0, 0, 0, 0, 0, 0};
 uchar*  pH = &(block[nSize - sha.dSize - 1]);
 uchar   digest[256];
 int     i = 0, j = sha.dSize << 1, k = pH - block;
 uint    nSeed = 0x9d2602bb; // ??????????????
 CTX     ctx;

 sha.Init(&ctx, sha.pIData);
 sha.Input(&ctx, pCtx, nCtxLen);
 sha.Digest(&ctx, digest);

 // Now create a pseudo random salt. Store it right after digest.
 nSeed                                            ^= *((uint*)digest);
 nSeed                                            += *((uint*)(digest + 4));
 *(uint*)&(digest[sizeof(digest) - sizeof(uint)]) ^= nSeed;
 sha.Input(&ctx, digest, sizeof(digest));
 sha.Digest(&ctx, digest + sha.dSize);

 if (nSeed == 0x0fd73d45)
 { // ?????????????????
  // This is For test RFC8448 only. Use a particular fixed salt
  static const uchar f_salt[32] = {0x9e, 0x79, 0x6c, 0x6c, 0xae, 0x55, 0x2f, 0x4b, 0xbd, 0xa8, 0x74, 0xd3, 0x3b, 0xb9, 0xf5, 0xa7, 0xb9, 0x81, 0x72, 0x44, 0x1b, 0x79, 0x54, 0xb4, 0x63, 0xce, 0xe3, 0xf3, 0xb1, 0x81, 0x88, 0x26};
  for (int l = 0; l < 32; l++) digest[sha.dSize + l] = f_salt[l];
 }

 // Calculate H
 sha.Init(&ctx, sha.pIData);
 sha.Input(&ctx, cnt, 8);
 sha.Input(&ctx, digest, sha.dSize << 1);
 sha.Digest(&ctx, pH);
 block[nSize - 1] = 0xbc;

 // Store the salt into the block, right before H.
 for (i = k; i-- > k - sha.dSize;) block[i] = digest[i + j - k];
 block[i] = 0x01;
 for (; i-- > 0;) block[i] = 0x00;

 for (i = 0; i < k; i++, j++)
 {
  if (j >= sha.dSize)
  {
   sha.Init(&ctx, sha.pIData);
   sha.Input(&ctx, pH, sha.dSize);
   sha.Input(&ctx, cnt, 4);
   sha.Digest(&ctx, digest);
   if (++cnt[3] == 0x00)
    if (++cnt[2] == 0x00)
     if (++cnt[1] == 0x00) ++cnt[0];
   j = 0;
  }
  block[i] ^= digest[j];
 }

 block[0] &= 0x7F;
}
//---------------------------------------------------------------------------------------------------
#ifdef DO_TEST_SSA
uint32_t SsaTest(const CIPHER& sha, const uint8_t* block, uint32_t nSize, const uint8_t* pCtx, uint32_t nCtxLen)
{
 uint8_t      cnt[8]{0, 0, 0, 0, 0, 0, 0, 0};
 const uchar* pH = &(block[nSize - sha.dSize - 1]);
 uchar        digest[256];
 int          i = 0, j = sha.dSize, k = 0;
 CTX          ctx;

 for (i = 0; i < nSize - sha.dSize - 1; i++, j++)
 {
  if (j >= sha.dSize)
  {
   sha.Init(&ctx, sha.pIData);
   sha.Input(&ctx, pH, sha.dSize);
   sha.Input(&ctx, cnt, 4);
   sha.Digest(&ctx, digest);
   if (++cnt[3] == 0x00)
    if (++cnt[2] == 0x00)
     if (++cnt[1] == 0x00) ++cnt[0];
   j = 0;
  }
  digest[j] ^= block[i];
  if (k)
  {
   digest[k++] = digest[j]; // This stores the salt
  }
  else if (digest[j] == 0x01)
  {
   k = sha.dSize;
   continue;
  }
  else if (i && digest[j]) { return -1; }
 }

 const uchar* pSalt    = &(digest[sha.dSize]);
 uint         nSaltLen = k - sha.dSize;
 *((uint*)cnt)         = 0;

 sha.Init(&ctx, sha.pIData);
 sha.Input(&ctx, pCtx, nCtxLen);
 sha.Digest(&ctx, digest);

 sha.Init(&ctx, sha.pIData);
 sha.Input(&ctx, cnt, 8);
 sha.Input(&ctx, digest, k);
 sha.Digest(&ctx, digest);

 for (i = 0; i < sha.dSize; i++)
  if (digest[i] ^= pH[i]) return -1;
 return 0;
}
#endif
//---------------------------------------------------------------------------------------------------
#endif //_SHA_H_INCLUDED_03_12_2019_
