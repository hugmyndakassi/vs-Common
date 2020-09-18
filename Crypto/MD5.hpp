
//==============================================================================
class CMD5
{
public:
static const int MD5Size = 16;

 bool   UpCaseStr;
 bool   NeedStrMD5;
 UINT8  StrResultMD5[(MD5Size*2)+2];
 UINT8  BinResultMD5[MD5Size];

private: 
 UINT8  lpszBuffer[64];
 UINT32 nCount[2];
 UINT32 lMD5[4];
 UINT8  PADDING[64];   // [0] must be = 0x80

//------------------------------------------------------------------------------
// ROTATE_LEFT rotates x left n bits.
static inline UINT32 ROTATE_LEFT32(UINT32 x, UINT8 n){return ((x << n) | (x >> (32-n)));}

// F, G, H and I are basic MD5 functions.
static inline UINT32 _F_(UINT32 x, UINT32 y, UINT32 z){return ((x & y) | (~x & z));}
static inline UINT32 _G_(UINT32 x, UINT32 y, UINT32 z){return ((x & z) | (y & ~z));}
static inline UINT32 _H_(UINT32 x, UINT32 y, UINT32 z){return (x ^ y ^ z);}
static inline UINT32 _I_(UINT32 x, UINT32 y, UINT32 z){return (y ^ (x | ~z));}

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
static inline void FF(UINT32& a, UINT32 b, UINT32 c,UINT32  d, UINT32 x, UINT8 s, UINT32 ac) {a = ROTATE_LEFT32(a + (_F_(b, c, d) + x + ac), s) + b;}
static inline void GG(UINT32& a, UINT32 b, UINT32 c,UINT32  d, UINT32 x, UINT8 s, UINT32 ac) {a = ROTATE_LEFT32(a + (_G_(b, c, d) + x + ac), s) + b;}
static inline void HH(UINT32& a, UINT32 b, UINT32 c,UINT32  d, UINT32 x, UINT8 s, UINT32 ac) {a = ROTATE_LEFT32(a + (_H_(b, c, d) + x + ac), s) + b;}
static inline void II(UINT32& a, UINT32 b, UINT32 c,UINT32  d, UINT32 x, UINT8 s, UINT32 ac) {a = ROTATE_LEFT32(a + (_I_(b, c, d) + x + ac), s) + b;}
//------------------------------------------------------------------------------
public:
static void MemClear(void* pData, UINT nLength)
{                       
 for(UINT i=(nLength / sizeof(void*));i > 0;i--,pData = ((void**)pData)+1)*((void**)pData)=0;  // 4/8 bytes, dependant on a platform
 for(UINT i=(nLength % sizeof(void*));i > 0;i--,pData = ((UINT8*)pData)+1)*((UINT8*)pData)=0;
}
//------------------------------------------------------------------------------
static UINT16 HexToChar(UINT8 Value, bool UpCase)
{
 UINT16 Result = 0;
 UINT8  Case   = UpCase ? 0x37 : 0x57;  // 'A' - 10
 for(int ctr=1;ctr >= 0;ctr--)
  {
   UINT8 Tmp = (Value & 0x0F);
   if(Tmp < 0x0A)((UINT8*)&Result)[ctr] |= 0x30+Tmp;  // 0 - 9
	 else ((UINT8*)&Result)[ctr] |= Case+Tmp;         // A - F
   Value  >>= 4;
  }
 return Result;
}
//------------------------------------------------------------------------------
// Str must be twice size of Array + 1
static char* ByteArrayToHexStr(PBYTE Array, UINT ArrSize, char* Str, bool UpCase)
{
 Str[ArrSize*2] = 0;
 for(UINT i=0;i < ArrSize;i++)
  {
   UINT16 chr   = HexToChar(Array[i],UpCase);
   Str[(i*2)]   = (UINT8)chr; 
   Str[(i*2)+1] = (UINT8)(chr >> 8);
  }
 return Str;
} 
//------------------------------------------------------------------------------
private:
// Decodes input (unsigned char) into output (UINT32). Assumes len is a multiple of 4.
static void ByteToDWord(UINT32* Output, UINT8* Input, UINT nLength)
{
 for(UINT i=0,j=0; j < nLength; i++, j += 4)Output[i] = (UINT32)Input[j] | (UINT32)Input[j+1] << 8 | (UINT32)Input[j+2] << 16 | (UINT32)Input[j+3] << 24;
}
//------------------------------------------------------------------------------
// Encodes input (UINT32) into output (unsigned char). Assumes len is a multiple of 4.
static void DWordToByte(UINT8* Output, UINT32* Input, UINT nLength)
{
 for(UINT i=0,j=0; j < nLength; i++, j += 4)
  {
   Output[j]   = (UINT8)Input[i];
   Output[j+1] = (UINT8)(Input[i] >> 8);
   Output[j+2] = (UINT8)(Input[i] >> 16);
   Output[j+3] = (UINT8)(Input[i] >> 24);
  }
}
//------------------------------------------------------------------------------
// The core of the MD5 algorithm is here. MD5 basic transformation. Transforms state based on block.
static void Transform(UINT32 *buf, UINT32 *in)
{
 UINT32 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

const UINT8 S11 = 7;
const UINT8 S12 = 12;
const UINT8 S13 = 17;
const UINT8 S14 = 22;
 FF ( a, b, c, d, in[ 0], S11, 0xD76AA478L); 
 FF ( d, a, b, c, in[ 1], S12, 0xE8C7B756L); 
 FF ( c, d, a, b, in[ 2], S13, 0x242070DBL); 
 FF ( b, c, d, a, in[ 3], S14, 0xC1BDCEEEL); 
 FF ( a, b, c, d, in[ 4], S11, 0xF57C0FAFL); 
 FF ( d, a, b, c, in[ 5], S12, 0x4787C62AL); 
 FF ( c, d, a, b, in[ 6], S13, 0xA8304613L); 
 FF ( b, c, d, a, in[ 7], S14, 0xFD469501L); 
 FF ( a, b, c, d, in[ 8], S11, 0x698098D8L); 
 FF ( d, a, b, c, in[ 9], S12, 0x8B44F7AFL); 
 FF ( c, d, a, b, in[10], S13, 0xFFFF5BB1L); 
 FF ( b, c, d, a, in[11], S14, 0x895CD7BEL); 
 FF ( a, b, c, d, in[12], S11, 0x6B901122L); 
 FF ( d, a, b, c, in[13], S12, 0xFD987193L); 
 FF ( c, d, a, b, in[14], S13, 0xA679438EL); 
 FF ( b, c, d, a, in[15], S14, 0x49B40821L); 

const UINT8 S21 = 5;
const UINT8 S22 = 9;
const UINT8 S23 = 14;
const UINT8 S24 = 20;
 GG ( a, b, c, d, in[ 1], S21, 0xF61E2562L); 
 GG ( d, a, b, c, in[ 6], S22, 0xC040B340L); 
 GG ( c, d, a, b, in[11], S23, 0x265E5A51L); 
 GG ( b, c, d, a, in[ 0], S24, 0xE9B6C7AAL); 
 GG ( a, b, c, d, in[ 5], S21, 0xD62F105DL); 
 GG ( d, a, b, c, in[10], S22, 0x02441453L); 
 GG ( c, d, a, b, in[15], S23, 0xD8A1E681L); 
 GG ( b, c, d, a, in[ 4], S24, 0xE7D3FBC8L); 
 GG ( a, b, c, d, in[ 9], S21, 0x21E1CDE6L); 
 GG ( d, a, b, c, in[14], S22, 0xC33707D6L); 
 GG ( c, d, a, b, in[ 3], S23, 0xF4D50D87L); 
 GG ( b, c, d, a, in[ 8], S24, 0x455A14EDL); 
 GG ( a, b, c, d, in[13], S21, 0xA9E3E905L); 
 GG ( d, a, b, c, in[ 2], S22, 0xFCEFA3F8L); 
 GG ( c, d, a, b, in[ 7], S23, 0x676F02D9L); 
 GG ( b, c, d, a, in[12], S24, 0x8D2A4C8AL); 

const UINT8 S31 = 4;
const UINT8 S32 = 11;
const UINT8 S33 = 16;
const UINT8 S34 = 23;
 HH ( a, b, c, d, in[ 5], S31, 0xFFFA3942L); 
 HH ( d, a, b, c, in[ 8], S32, 0x8771F681L); 
 HH ( c, d, a, b, in[11], S33, 0x6D9D6122L); 
 HH ( b, c, d, a, in[14], S34, 0xFDE5380CL); 
 HH ( a, b, c, d, in[ 1], S31, 0xA4BEEA44L);
 HH ( d, a, b, c, in[ 4], S32, 0x4BDECFA9L); 
 HH ( c, d, a, b, in[ 7], S33, 0xF6BB4B60L); 
 HH ( b, c, d, a, in[10], S34, 0xBEBFBC70L); 
 HH ( a, b, c, d, in[13], S31, 0x289B7EC6L); 
 HH ( d, a, b, c, in[ 0], S32, 0xEAA127FAL); 
 HH ( c, d, a, b, in[ 3], S33, 0xD4EF3085L); 
 HH ( b, c, d, a, in[ 6], S34, 0x04881D05L);
 HH ( a, b, c, d, in[ 9], S31, 0xD9D4D039L); 
 HH ( d, a, b, c, in[12], S32, 0xE6DB99E5L); 
 HH ( c, d, a, b, in[15], S33, 0x1FA27CF8L); 
 HH ( b, c, d, a, in[ 2], S34, 0xC4AC5665L); 

const UINT8 S41 = 6;
const UINT8 S42 = 10;
const UINT8 S43 = 15;
const UINT8 S44 = 21;
 II ( a, b, c, d, in[ 0], S41, 0xF4292244L); 
 II ( d, a, b, c, in[ 7], S42, 0x432AFF97L); 
 II ( c, d, a, b, in[14], S43, 0xAB9423A7L); 
 II ( b, c, d, a, in[ 5], S44, 0xFC93A039L); 
 II ( a, b, c, d, in[12], S41, 0x655B59C3L); 
 II ( d, a, b, c, in[ 3], S42, 0x8F0CCC92L); 
 II ( c, d, a, b, in[10], S43, 0xFFEFF47DL); 
 II ( b, c, d, a, in[ 1], S44, 0x85845DD1L); 
 II ( a, b, c, d, in[ 8], S41, 0x6FA87E4FL); 
 II ( d, a, b, c, in[15], S42, 0xFE2CE6E0L); 
 II ( c, d, a, b, in[ 6], S43, 0xA3014314L); 
 II ( b, c, d, a, in[13], S44, 0x4E0811A1L); 
 II ( a, b, c, d, in[ 4], S41, 0xF7537E82L); 
 II ( d, a, b, c, in[11], S42, 0xBD3AF235L); 
 II ( c, d, a, b, in[ 2], S43, 0x2AD7D2BBL); 
 II ( b, c, d, a, in[ 9], S44, 0xEB86D391L); 

 buf[0] += a;
 buf[1] += b;
 buf[2] += c;
 buf[3] += d;
}
//------------------------------------------------------------------------------
public:
CMD5(bool scase=true, bool nstrv=false)
{
 this->UpCaseStr  = scase;
 this->NeedStrMD5 = nstrv;
 this->Initialize();
}
//------------------------------------------------------------------------------
void Initialize(void)
{
 bool scase = this->UpCaseStr;
 bool nstrv = this->NeedStrMD5;
 MemClear(this, sizeof(CMD5));
 this->UpCaseStr  = scase;
 this->NeedStrMD5 = nstrv;
 this->PADDING[0] = 0x80;

 this->lMD5[0]  = 0x67452301;  // Load magic initialization constants.
 this->lMD5[1]  = 0xefcdab89;
 this->lMD5[2]  = 0x98badcfe;
 this->lMD5[3]  = 0x10325476;
}
//------------------------------------------------------------------------------
// MD5 block update operation. Continues an MD5 message-digest operation, processing another message block, and updating the context.
void Update(UINT8* inBuf, UINT inLen)
{
 int mdi = (int)((this->nCount[0] >> 3) & 0x3F);
 if((this->nCount[0] + ((UINT32)inLen << 3)) < this->nCount[0])this->nCount[1]++;
 this->nCount[0] += ((UINT32)inLen << 3);
 this->nCount[1] += ((UINT32)inLen >> 29);

 while (inLen--)
  {
   this->lpszBuffer[mdi++] = *inBuf++;
   if (mdi == 0x40)          // TODO: Optimize
    {
     UINT32 in[16];
	 for(int i = 0, ii = 0; i < 16; i++, ii += 4)in[i] = (((UINT32)this->lpszBuffer[ii+3]) << 24) | (((UINT32)this->lpszBuffer[ii+2]) << 16) | (((UINT32)this->lpszBuffer[ii+1]) << 8) | ((UINT32)this->lpszBuffer[ii]);
	 this->Transform(this->lMD5, in);
     mdi = 0;
    }
  }
}
//------------------------------------------------------------------------------
// MD5 finalization. Ends an MD5 message-digest operation, writing the the message digest and zeroizing the context.
void Finalize(void)
{
 UINT8 bits[8];

 DWordToByte(bits, this->nCount, 8);
 int  nIndex  = (int)((this->nCount[0] >> 3) & 0x3f);
 UINT nPadLen = (nIndex < 56) ? (56 - nIndex) : (120 - nIndex);
 this->Update (this->PADDING, nPadLen);
 this->Update(bits, 8);
 DWordToByte(&this->BinResultMD5[0], this->lMD5, MD5Size);
 if(this->NeedStrMD5)
  {
   this->StrResultMD5[MD5Size*2] = 0;
   for(int i=0;i < MD5Size;i++)
    {
     UINT16 chr = HexToChar(this->BinResultMD5[i],this->UpCaseStr);
     this->StrResultMD5[(i*2)]   = ((UINT8*)&chr)[0];
     this->StrResultMD5[(i*2)+1] = ((UINT8*)&chr)[1];
    }
  }
}
//------------------------------------------------------------------------------
UINT8* GetMD5(UINT8* pBuf, UINT nLength)
{
 this->Initialize();
 this->Update(pBuf, nLength);
 this->Finalize();
 return (UINT8*)&this->BinResultMD5;
}
//------------------------------------------------------------------------------
};
