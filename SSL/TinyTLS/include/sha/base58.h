#ifndef BASE58__H_INCLUDED
#define BASE58__H_INCLUDED
#pragma once

#include <stdint.h>
#include "../../include/sha/base58.h"
#include "../../include/ecc/ecc.h"

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

struct N58: NN
{
 //---------------------------------------------------------------------------------------------------
 uint32_t N58::reduce58()
 {
  uint32_t r = 0, q = 0;
  for (uint32_t i = N; i-- > 0;)
  {
   q       = n_[i] / 58;
   n_[i]  -= q * 58;
   q      += r * 74051160;
   r     <<= 4;
   r      += n_[i];
   n_[i]   = q;
   q       = r / 58;
   n_[i]  += q;
   r      -= q * 58;
  }
  return r;
 }
 //---------------------------------------------------------------------------------------------------
 void N58::madd58(uint8_t a)
 {
  uint32_t r = 0, q = 0, v(a);
  NN       n(*this);
  *this <<= 6;
  n     <<= 1;
  *this  -= n;
  n     <<= 1;
  *this  -= n;
  for (uint32_t i = 0; i < N; i++)
  {
   n_[i] += a;
   if (n_[i] >= a) break;
   a = 1;
  }
 }
 //---------------------------------------------------------------------------------------------------
};




//---------------------------------------------------------------------------------------------------
static uint32_t base58Encode(const uint8_t* pIn, uint32_t cbSize, char* pOut)
{
 // https://en.bitcoin.it/wiki/Base58Check_encoding
 static const uint8_t sCode[]{"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"};
 uint8_t              bData[32];
 uint8_t              bOut[48];
 uint8_t*             p  = bOut;
 char*                p0 = pOut;
 while (*pIn == 0x00)
 {
  pIn++;
  cbSize--;
  *pOut++ = '1';
 }
 memset(bData, 0, sizeof(bData));
 memcpy(bData + 32 - cbSize, pIn, cbSize);
 N58 n;
 n.netIn(bData);
 do {
  *p++ = n.reduce58();
 } while (!n.is0());
 while (p-- > bOut) *pOut++ = sCode[*p];
 *pOut = 0x00;
 return pOut - p0;
}
//---------------------------------------------------------------------------------------------------
static uint32_t base58Decode(const char* pIn, uint32_t cbSize, uint8_t* pOut)
{
 uint8_t* p0 = pOut;
 while (*pIn == '1')
 {
  pIn++;
  cbSize--;
  *pOut++ = 0x00;
 }

 N58 n;
 while (cbSize--)
 {
  uint8_t v(*pIn++);
  if (v > 'k') v--;
  if (v > 'Z') v -= 0x06;
  if (v > 'N') v--;
  if (v > 'H') v--;
  if (v > '9') v -= 0x07;
  v -= '1';
  n.madd58(v);
 }
 uint8_t* p = ((uint8_t*)n.n_) + (n.N << 2);
 while (*--p == 0x00) { }
 while (p >= ((uint8_t*)n.n_)) *pOut++ = *p--;
 return pOut - p0;
}
//---------------------------------------------------------------------------------------------------

#ifdef __cplusplus
} // extern "C"
#endif //__cplusplus

#endif // BASE58__H_INCLUDED
