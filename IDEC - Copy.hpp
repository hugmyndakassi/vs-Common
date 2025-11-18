
#pragma once

//---------------------------------------------------------------------------

// Based on: https://github.com/DispatchCode/x64-Instruction-Decoder

struct SIDEC
{

using sint8  = char;
using uint8  = unsigned char;
using sint16 = short;
using uint16 = unsigned short;
using sint32 = int;
using uint32 = unsigned int;
using sint64 = long long;
using uint64 = unsigned long long;

/*
template<typename V, typename T, usize N> struct CBData    // alignas(8) // !!! Cannot be used as a function argument: argument deduction not allowed in a function prototype
{
 SCVR usize ChrInUnit = sizeof(usize) / sizeof(V);      // !!! Cannot pack u64 on a x32 system!
 SCVR usize BytesLen  = sizeof(V) * N;     // Size  (Str including 0)
 SCVR usize WholeLen  = (BytesLen / sizeof(usize));
 SCVR usize ArrSize   = WholeLen + (bool)(BytesLen & (sizeof(usize) - 1));  // FullSize (Allocated)
 
 usize Array[ArrSize];

 // A type is a literal type if: it has a trivial destructor... // A destructor is trivial if it is not user-provided... // Cannot use with the destructor as an user defined literal!
 //_finline ~CPData() {for(uint idx=0,vo=N*sizeof(T);idx < ArrSize;vo=Array[idx],idx++)Array[idx] = (Array[idx] * N) ^ vo;}  // Implement stack cleaning on destruction  // <<<<<<<<<<<<< Move this to decrypted string holder
 consteval void Init(const T* str)
 {
  for(usize sidx = 0, didx = 0; sidx < N; didx++, sidx += ChrInUnit)this->Array[didx] = RePackElements<usize,decltype(str)>(&str[sidx], N - sidx);
 }
 constexpr _finline operator const V* () const { return (V*)this->Array; }
 constexpr _finline V* Ptr() const { return (V*)this->Array; }        // Call it after decryption!
 constexpr static _finline usize Size(void) {return N;}  // In bytes
};

template<typename T, usize N> struct CPBits: CBData<T,T,N>
{
 consteval CPStr(const T* str, usize l) { this->Init(str); }  // Must have an useless arg to be different from another constructor
 consteval CPStr(const T(&str)[N]) { this->Init(str); }
 constexpr static _finline usize Size(void) {return N-1;}  // In chars, without 0  // Or should include the 0?
};
*/

enum supported_architecture {
    X86 = 1,
    X64 = 2
};

/*enum decode_status {
    ERROR = 0
}; */

#define ALL (X86 | X64)

//
// instruction prefix look-up table
static const inline size_t x86_64_prefix[256] = {
        //       00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
        /* 00 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  ALL,
        /* 10 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* 20 */ 0,  0,  0,  0,  0,  0,  ALL,0,  0,  0,  0,  0,  0,  0,  ALL,0,
        /* 30 */ 0,  0,  0,  0,  0,  0,  ALL,0,  0,  0,  0,  0,  0,  0,  ALL,0,
        /* 40 */ X64,X64,X64,X64,X64,X64,X64,X64,X64,X64,X64,X64,X64,X64,X64,X64, // REX prefixes
        /* 50 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* 60 */ 0,  0,  0,  0,  ALL,ALL,ALL,ALL,0,  0,  0,  0,  0,  0,  0,  0,
        /* 70 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* 80 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* 90 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* A0 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* B0 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* C0 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* D0 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* E0 */ 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        /* F0 */ ALL,0,ALL,  ALL,0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

//
// 1-byte lookup table
//
#define X87_FPU  2

static const inline size_t modrm_1b[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
        /* 10 */ 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
        /* 20 */ 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
        /* 30 */ 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
        /* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */ 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */ 1, 1, 1, 1, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, // 2 = Coprocessor Escape
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */ 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1
};

#define   b   1 // byte
#define   v   2 // word, dword or qword (64bit mode), depending on OS attribute
#define   z   3 // word for 16bit OS or dword for 32/64-bit OS
#define   p   4 // 32-bit, 48-bit, or 80-bit pointer, depending on operand-size attribute
#define   z1  6 // word for 16bit OS or dword for 32/64-bit OS
#define   w   7 // word
#define   wb  8 // word, byte
#define   gr3b  9 // byte (imm exists only if mod.reg == 0)
#define   gr3z  10 // word, dword depending on OS (imm exists only if mod.reg == 0)

static const inline size_t imm_byte_1b[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 0, 0, 0, 0, b, z, 0, 0, 0, 0, 0, 0, b, z, 0, 0,
        /* 10 */ 0, 0, 0, 0, b, z, 0, 0, 0, 0, 0, 0, b, z, 0, 0,
        /* 20 */ 0, 0, 0, 0, b, z, 0, 0, 0, 0, 0, 0, b, z, 0, 0,
        /* 30 */ 0, 0, 0, 0, b, z, 0, 0, 0, 0, 0, 0, b, z, 0, 0,
        /* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, z, z, b, b, 0, 0, 0, 0,
        /* 70 */ b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b,
        /* 80 */ b, z, b, b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, p, 0, 0, 0, 0, 0,
        /* A0 */ z1,z1,z1,z1, 0, 0, 0, 0, b, z, 0, 0, 0, 0, 0, 0,
        /* B0 */ b, b, b, b, b, b, b, b, v, v, v, v, v, v, v, v,
        /* C0 */ b, b, w, 0, 0, 0, b, z, wb, 0, w, 0, 0, b, 0, 0,
        /* D0 */ 0, 0, 0, 0, b, b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */ b, b, b, b, b, b, b, b, z, z, p, b, 0, 0, 0, 0,
        /* F0 */ 0, 0, 0, 0, 0, 0, gr3b, gr3z, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * first byte:
 *   - 1: 1-byte
 *   - 2: 4-byte
 *
 * second byte (LSB):
 *   - 1: Jcc
 *   - 2: JMP
 *
 */
#define j1  0x12
#define j2  0x22
#define jc1 0x11
#define jc2 0x21

// check if the OP is Jcc or JMP     // JECXZ [E3] ???
static const inline size_t op1b_labels[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1, jc1,
        /* 80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, j2, 0, j1, 0, 0, 0, 0,
        /* F0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//
// 2-byte OP look-up table

// 0x0f
#define  OE   0x01
// 0x66 0x0f
#define  O66  0x02
// 0xf2 0x0f
#define  OF2  0x04
// 0xf3 0x0f
#define  OF3  0x08

#define  P1   (OE)
#define  P2   (O66 | OE)
#define  P4   (OF3 | OE)
#define  P5   (O66 | OF2)
#define  P6   (OE  | O66 | OF3)
#define  P7   (OE  | O66 | OF2 | OF3)
#define  P8   (O66 | OF2 | OF3)

static const inline size_t modrm_2b[256] = {
        //       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ P1,P1,P1,P1,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */ P7,P7,P7,P2,P2,P2,P6,P2,P1,0, 0, 0, 0, 0, 0, P1,
        /* 20 */ P1,P1,P1,P1,0, 0, 0, 0, P2,P2,P7,P2,P7,P7,P2,P2,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 40 */ P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,
        /* 50 */ P2,P7,P4,P4,P2,P2,P2,P2,P7,P7,P7,P6,P7,P7,P7,P7,
        /* 60 */ P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,O66,O66,P2,P2,
        /* 70 */ P7,P1,P1,P1,P2,P2,P2,P1,P1,P1, 0, 0,P5,P5,P6,P6,
        /* 80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */ P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,P1,
        /* A0 */ 0, 0, 0, P1,P1,P1, 0, 0, 0, 0, 0,P1,P1,P1,P1,P1,
        /* B0 */ P1,P1,P1,P1,P1,P1,P1,P1,OF3,P1,P1,P1,P4,P4,P1,P1,
        /* C0 */ P1,P1,P7,P1,P2,P2,P2,P1, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */ P5,P2,P2,P2,P2,P2,P8,P2,P2,P2,P2,P2,P2,P2,P2,P2,
        /* E0 */ P2,P2,P2,P2,P2,P2,P8,P2,P2,P2,P2,P2,P2,P2,P2,P2,
        /* F0 */ OF2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2, 0
};

static const inline size_t imm_byte_2b[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ b, b, b, b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ z, z, z, z, z, z, z, z, z, z, z, z, z, z, z, z,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, b, 0, 0, 0, 0, 0, 0, 0, b, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b, 0, 0, 0, 0, 0,
        /* C0 */ 0, 0, b, 0, b, b, b, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// check if the OP is Jcc or JMP
static const inline size_t op2b_labels[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2, jc2,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//
// 3-byte OP look-up table

#define OP3 (OE | OF2 | O66)
#define OP2 (OE | OF2 | OF3)
#define OP4 (O66 | OF2 | OF3)

//
// 3-byte OP look-up table (0x38)
static const inline size_t modreg_3b_38[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,O66,O66,O66,O66,
        /* 10 */ O66,0,0,O66,O66,O66,O66,O66,0,0,0,0,O66,O66,O66,0,
        /* 20 */ O66,O66,O66,O66,O66,O66,0,0,O66,O66,O66,O66,O66,O66,O66,O66,
        /* 30 */ O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
        /* 40 */ O66,O66, 0, 0, 0, O66,O66,O66, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ O66,O66,O66,0, 0, 0, 0, 0, 0, 0, 0, 0,O66,0,O66,0,
        /* 90 */ O66,O66,O66,O66, 0, 0,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
        /* A0 */ 0, 0, 0, 0, 0, 0, O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
        /* B0 */ 0, 0, 0, 0, 0, 0, O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
        /* C0 */ 0, 0, 0, 0, 0, 0, 0, 0, O66,O66,O66,O66,O66,O66,O66,O66,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, O66, O66, O66, O66, O66,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, O66, O66, O66, O66, O66,
        /* F0 */ OP3, OP3, OE, 0, 0, OP2, OP4, P7, 0, 0, 0, 0, 0, 0, 0, 0
};

static const inline size_t imm_byte_3b_38[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 20 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define OP5 (OE | O66)

//
// 3-byte OP look-up table (0x3A)

static const inline size_t modreg_3b_3A[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ O66, O66, O66, 0, O66, O66, O66, 0, O66, O66, O66, O66,O66 , O66, O66, OP5,
        /* 10 */ 0, 0, 0, 0, O66, O66, O66, O66, O66, O66, 0, 0, 0, O66, 0, 0,
        /* 20 */ O66, O66, O66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, O66, O66, 0, 0, 0, 0, 0, 0,
        /* 40 */ O66, O66, O66, 0, O66, 0, O66, 0, 0, 0, O66, O66, O66, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ O66, O66, O66, O66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, O66, 0, 0, 0,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, O66,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */ OF2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const inline size_t imm_byte_3b_3A[256] = {
        //      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */ 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 10 */ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0,
        /* 20 */ 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        /* 40 */ 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0,
        /* 50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */ 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        /* D0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        /* E0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

enum jmp_type {
    JCC_SHORT = 1,  // 1-byte JCC
    JCC_FAR   = 2,  // 2-byte JCC, 4bytes imm
    JMP_SHORT = 4,  // 1-byte JMP
    JMP_FAR   = 8,  // 4-byte JMP
};

enum prefixes {
    ES = 1,  // 0x26
    CS = 2,  // 0x2E
    SS = 4,  // 0x36
    DS = 8,  // 0x3E
    FS = 16, // 0x64
    GS = 32, // 0x65
    OS = 64, // 0x66
    AS = 128,// 0x67
    REPNE  = 256,
    REPE   = 512,
    OP64   = 1024,
    VEX    = 2048
};

enum instruction_feature {
    PREFIX = 1,
    ESCAPE = 2, // 0x0F
    OP     = 4,
    OP3B   = 8,
    MODRM  = 16,
    SIB    = 32,
    REX    = 64,
    DISP   = 128,
    IMM    = 512,
    FPU    = 1024,
};

//
// VEX FORMAT
//
// 3-byte VEX bit   7      0 765 4    0 7 6  3 2  0
//                  11000100 RXB m-mmmm W vvvv L pp
//
// 2-byte VEX bit   7      0 7 6  3 2  0
//                  11000101 R vvvv L pp
//
// pp: equivalent to a SIMD prefix
//      00 : None
//      01 : 0x66
//      02 : 0xF3
//      03 : 0xF2
//
// m-mmmm:
//      00000: Reserved for future use (will #UD)
//      00001: implied 0F leading opcode byte
//      00010: implied 0F 38 leading opcode bytes
//      00011: implied 0F 3A leading opcode bytes
//      00100-11111: Reserved for future use (will #UD)
//
//


struct vex_info 
{
    struct {
        uint8 type;
        union {
            struct byte2 {
                uint8 vex_pp : 2;
                uint8 vex_l  : 1;
                uint8 vex_v  : 4;
                uint8 vex_r  : 1;
            } vexc5b;
            uint8 val5;
        };
        union {
            struct byte3 {
                uint8 vex_m : 5;
                uint8 vex_b : 1;
                uint8 vex_x : 1;
                uint8 vex_r : 1;

                uint8 vex_pp : 2;
                uint8 vex_l  : 1;
                uint8 vex_v  : 4;
                uint8 vex_w  : 1;
            } vexc4b;
            uint16 val4;
        };
    };
};

//---------------------------------------------------------------------------

 uint64 disp;
 uint64 imm;
 size_t label;
 uint8  prefixes[4];
 uint8  op;

 union
 {
     struct
     {
         uint8 rm  : 3;
         uint8 reg : 3;
         uint8 mod : 2;
     } bits;
     uint8 value;
 } modrm;

 union
 {
     struct
     {
         uint8 rex_b : 1;
         uint8 rex_x : 1;
         uint8 rex_r : 1;
         uint8 rex_w : 1;
     } bits;
     uint8 value;
 } rex;

 union
 {
     struct
     {
         uint8  base   : 3;
         uint8  index  : 3;
         uint8  scaled : 2;
     } bits;
     uint8 value;
 } sib;

 uint8 vex[3];

 int length;
 int disp_len;
 int imm_len;

 uint16 set_prefix; // bit mask
 uint16 set_field;
 uint8  jcc_type;

 sint8 vex_cnt;       // Signed?
 sint8 prefix_cnt;

 vex_info vexi;
   /*
private:

static inline bool check_sib(uint8 mod, uint8 rm) { return (mod < 3) && (rm == 4); }
//---------------------------------------------------------------------------
static inline int displacement_size(uint8 mod, uint8 rm)
{
 if((mod == 0x02) || (rm == 0x05 && !mod)) return 4;
   else if(mod == 0x01) return 1;
 return 0;
}
//---------------------------------------------------------------------------
inline void vex_decode(enum supported_architecture arch, const uint8* data, uint8 vex_size)
{
 memcpy(this->vex, &data[this->length], vex_size);
 this->vex_cnt += vex_size;
 this->length  += vex_size;

 this->op = data[this->length];
 this->length++;

 this->set_prefix |= VEX;
 if(this->vex[0] == 0xC5)
  {
   this->vexi.type = this->vex[0];
   this->vexi.val5 = this->vex[1];
   this->decode_modrm(arch, data, modrm_2b, imm_byte_2b, nullptr);
  }
   else if(this->vex[0] == 0xC4)
    {
     this->vexi.type = this->vex[0];
     memcpy(&this->vexi.val4, &this->vex[1], 2);
    
     sint8 index = this->vex[1] & 0x3;
     if(index)
      {
       const size_t* imm_table[4]   = {0, imm_byte_2b, imm_byte_3b_38, imm_byte_3b_3A};    // NOTE: Make sure thet the compiler does not make it static
       const size_t* modrm_table[4] = {0, modrm_2b, modreg_3b_38, modreg_3b_3A};
       this->decode_modrm(arch, data, modrm_table[index], imm_table[index], nullptr);   // 'if(index)' - We should not crash!
      }
    }
 // TODO  XOP, 0x8F
}
//---------------------------------------------------------------------------
inline int vex_size(enum supported_architecture arch, const uint8* data)
{
 data += this->length;
 uint8 curr_byte = *data;
 uint8 next_byte = data[1];
 // 3-byte VEX prefix
 if((arch == X86 && curr_byte == 0xC4 && (next_byte >> 6) == 3) || (arch == X64 && curr_byte == 0xC4)) return 3;
 // 2-byte VEX prefix
   else if((arch == X86 && curr_byte == 0xC5 && (next_byte & 0x80)) || (arch == X64 && curr_byte == 0xC5)) return 2;
 return 0;
}
//---------------------------------------------------------------------------
inline int imm_size(size_t val, enum supported_architecture arch)
{
 switch(val)
  {
   case b:
    return 1;
   case v:
    if(arch == X64 && this->set_prefix & OP64) return 8;
    if(this->set_prefix & OS) return 2;
    return 4;
   case z:
   case z1:
    if(this->set_prefix & OS) return 2;
    return 4;
   case p:
    if(this->set_prefix & OS)
    {
     if(arch == X86) return 4;
     return 8;
    }
    return 6;
   case w:
    return 2;
   case wb:
    return 3; // TODO  ENTER iw, ib
   case gr3b:
    if(!this->modrm.bits.reg) return 1;
    return 0;
   case gr3z:
    if(!this->modrm.bits.reg)
    {
     if(this->set_prefix & OS) return 2;
     return 4;
    }
    return 0;
  
   default:
    return 0;
  }
}
//---------------------------------------------------------------------------
void decode_modrm(enum supported_architecture arch, const uint8* data, const size_t* modrm_table, const size_t* imm_table, const size_t* jcc_table)
{
 size_t val;
 if((val = modrm_table[this->op]))
  {
   this->set_field |= MODRM;
   if (val == X87_FPU) this->set_field |= FPU; 
   uint8 curr = data[this->length];  // *(start_data + this->length); 
   this->modrm.value = curr;
   this->length++;
   uint8 mod_val = this->modrm.bits.mod, rm_val = this->modrm.bits.rm;
  
   if(check_sib(this->modrm.bits.mod, this->modrm.bits.rm))
    {
     this->set_field |= SIB;    
     this->sib.value = data[this->length];  //(uint8_t)*(start_data + this->length);
     this->length++;
    
     if(this->sib.bits.base == 0x05)
      {
       this->set_field |= DISP;
       mod_val          = this->modrm.bits.mod;
       rm_val           = this->sib.bits.base;
      }
    }
  
   this->disp_len = displacement_size(mod_val, rm_val);
   if(this->disp_len || this->set_field & DISP)
    {
     memcpy(&this->disp, &data[this->length], this->disp_len);
     this->length    += this->disp_len;
     this->set_field |= DISP;
    }
  }

 this->imm_len = this->imm_size(imm_table[this->op], arch);
 if(this->imm_len)
  {
   this->set_field |= IMM;
   memcpy(&this->imm, &data[this->length], this->imm_len);
   this->length += this->imm_len;
  }

 uint16 value = 0;
 if(jcc_table != NULL && (value = jcc_table[this->op]))       // !!!!!!!!!!!! TODO: Not just jmp - flag any control transfer (if needed at all)
  {
   switch(value)
    {
     case j1:
      this->jcc_type = JMP_SHORT;
      break;
     case j2:
      this->jcc_type = JMP_FAR;
      break;
     case jc1:
      this->jcc_type = JCC_SHORT;
      break;
     case jc2:
      this->jcc_type = JCC_FAR;
     default:
      break; // avoid compiler warnings
    }

   // 1-byte
   if(value & 0x10) this->label = (size_t)(data + ((sint8)this->imm) + this->length); // Overflow?   // RelAddrToAddr
   // 4-byte
     else this->label = (size_t)(data + ((sint64)this->imm) + this->length);    // Overflow?
  }
}
//---------------------------------------------------------------------------
int decode_2b(enum supported_architecture arch, const uint8* data)
{
 this->set_prefix |= ESCAPE;
 uint8 curr        = data[this->length];   //*(data_src + this->length);

 if(curr == 0x3A || curr == 0x38)
  {
   this->set_prefix |= OP3B;
   this->prefixes[this->prefix_cnt++] = curr;
   this->length++;
   this->op = data[this->length];  //*(data_src + this->length);
   this->length++;
  
   if(curr == 0x3A) this->decode_modrm(arch, data, modreg_3b_3A, imm_byte_3b_3A, nullptr);
     else this->decode_modrm(arch, data, modreg_3b_38, imm_byte_3b_38, nullptr);
   return this->length;
  }

 this->op = curr;
 this->length++;
 this->decode_modrm(arch, data, modrm_2b, imm_byte_2b, op2b_labels);
 return this->length;
}
//---------------------------------------------------------------------------
public:
int Decode(enum supported_architecture arch, const void* code)
{
 memset(this, 0, sizeof(*this));

 const uint8* data = (const uint8*)code;
 uint8 curr = *data;

 while(x86_64_prefix[curr] & arch)
  {
   switch(curr)
    {
     case 0x26:
      this->set_prefix |= ES;
      break;
     case 0x2E:
      this->set_prefix |= CS;
      break;
     case 0x36:
      this->set_prefix |= SS;
      break;
     case 0x3E:
      this->set_prefix |= DS;
      break;
     case 0x48:
     case 0x49:
      if (arch == X64) this->set_prefix |= OP64;
      break;
     case 0x64:
      this->set_prefix |= FS;
      break;
     case 0x65:
      this->set_prefix |= GS;
      break;
     case 0x66:
      this->set_prefix |= OS;
      break;
     case 0x67:
      this->set_prefix |= AS;
      break;
    }
  
   this->set_field                  |= PREFIX;
   this->prefixes[this->prefix_cnt]  = curr;
   this->prefix_cnt++;
   this->length++;
  
   // Rex prefix
   // TODO 64-bit mode: IF OP == 90h and REX.B == 1, then the instruction is XCHG r8, rAX
   if(arch == X64 && (curr >= 0x40 && curr <= 0x4F))
    {
     this->rex.value  = curr;
     this->set_field |= REX;
    }
     else if(curr == 0x0F)
      {
       this->decode_2b(arch, data);
       return this->length;
      }
  
   curr = data[this->length];  //(uint8)*(data + this->length);
  }

 size_t vex_size = this->vex_size(arch, data);
 if(vex_size) this->vex_decode(arch, data, vex_size);
  else
   {
    this->length++;
    this->op = curr;
    this->decode_modrm(arch, data, modrm_1b, imm_byte_1b, op1b_labels);
   }

 return this->length;
}
//---------------------------------------------------------------------------
// Templated to accept not only pointers
template<typename T> inline static sint32 AddrToRelAddr(T CmdAddr, uint8 CmdLen, T TgtAddr){return -((CmdAddr + CmdLen) - TgtAddr);}       
template<typename T> inline static T      RelAddrToAddr(T CmdAddr, uint8 CmdLen, sint32 TgtOffset){return ((CmdAddr + CmdLen) + TgtOffset);}  
*/
};
//---------------------------------------------------------------------------