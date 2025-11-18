
#pragma once

//---------------------------------------------------------------------------
// https://www.righto.com/2023/07/undocumented-8086-instructions.html
// https://wiki.osdev.org/X86-64_Instruction_Encoding

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
using size_t = SIZE_T;

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

// INTEL: instruction-length limit is 15 bytes

enum supported_architecture {
    X32 = 1,
    X64 = 2
};

enum EStatus: int 
{
    dsOK = 0,
    dsTooLong = -1
};

// Bits 4-7 = subtype (e.g. SEG=1, REP=2, LOCK=3, 0F escape=4, 38 escape=5…)
enum EByteRole : uint8 
{
 brNone      = 0x00,
 brPrefix    = 0x01,  // Legacy prefix
 brEscape    = 0x02,
 brOpcode    = 0x03,
 brModRM     = 0x04,
 brSib       = 0x05,
 brDisp      = 0x06,
 brImm       = 0x07,
 brRex       = 0x08   // REX prefixes (0x40–0x4F) (x64 only)
};

enum EByteType : uint8 
{
 btNone    = 0x00,

 // Prefix subtypes
 btLock    = 0x10,   // F0
 btRepNE   = 0x20,   // F2
 btRepE    = 0x30,   // F3
 btOprnd   = 0x40,   // 66   // Alt operand size
 btAddr    = 0x50,   // 67   // Alt address size
 btSegCS   = 0x60,   // 2E
 btSegSS   = 0x70,   // 36
 btSegDS   = 0x80,   // 3E
 btSegES   = 0x90,   // 26
 btSegFS   = 0xA0,   // 64
 btSegGS   = 0xB0,   // 65

 // Escape subtypes
 btEsc0F   = 0xC0,
 btEsc38   = 0xD0,
 btEsc3A   = 0xE0,
};

enum jmp_type {
    JCC_SHORT = 1,  // 1-byte JCC
    JCC_FAR   = 2,  // 2-byte JCC, 4bytes imm
    JMP_SHORT = 4,  // 1-byte JMP
    JMP_FAR   = 8,  // 4-byte JMP
};

// In x86-64, you can have at most 4 'legacy' prefixes per instruction, one from each group:
//   Lock/rep group: F0, F2, F3
//   Segment override group: 2E, 36, 3E, 26, 64, 65
//   Operand-size override: 66
//   Address-size override: 67
// 
// Architecturally, only one prefix per group is supposed to matter. 
// But the CPU happily accepts redundant ones (multiple 66s, multiple F3s, etc.), 
// and Intel/AMD manuals say 'any number of prefixes may be present' — up to the instruction-length limit of 15 bytes. 
// So worst-case: you could see 11 redundant prefixes in front of an opcode.
// 
// Max:
//   0–11 legacy prefixes (practically, 0–4 meaningful)
//   0–1 REX  // X64: (0x40–0x4F)
// Instead of legacy+REX, you can also get VEX (2 or 3 bytes) or EVEX (4 bytes), which replace them.
// 
// Opcode escape bytes ('escapes')
//
// These are not prefixes, just opcode extensions:
//   0F -> 2-byte opcode map
//   0F 38 -> 3-byte map
//   0F 3A -> another 3-byte map
//
// VEX/EVEX encodings imply those maps internally.
// So the maximum explicit escape chain is just:
//  1 byte (0F), or
//  2 bytes (0F 38 or 0F 3A).
// No more than 2 escapes in legacy form.
// 
// The Intel/AMD manuals explicitly say all prefixes must come before the opcode (including escapes). The valid instruction byte layout is:
//  [prefixes] [opcode escape(s)] [primary opcode byte] [ModR/M] [SIB] [disp] [imm]
//
enum prefixes {
    ES     = 1,    // 0x26
    CS     = 2,    // 0x2E
    SS     = 4,    // 0x36
    DS     = 8,    // 0x3E
    FS     = 16,   // 0x64
    GS     = 32,   // 0x65
    OS     = 64,   // 0x66  // Operand size override
    AS     = 128,  // 0x67  // Address size override
    REPNE  = 256,
    REPE   = 512,
    OP64   = 1024,
    VEX    = 2048,
    LOCK   = 4096  // 
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


enum ETblFlags: size_t
{
ALL = (X32 | X64),

// 1-byte lookup table
X87_FPU = 2,

  b    = 1, // byte
  v    = 2, // word, dword or qword (64bit mode), depending on OS attribute
  z    = 3, // word for 16bit OS or dword for 32/64-bit OS
  p    = 4, // 32-bit, 48-bit, or 80-bit pointer, depending on operand-size attribute
  z1   = 6, // word for 16bit OS or dword for 32/64-bit OS
  w    = 7, // word
  wb   = 8, // word, byte
  gr3b = 9, // byte (imm exists only if mod.reg == 0)
  gr3z = 10, // word, dword depending on OS (imm exists only if mod.reg == 0)

// 2-byte OP look-up table

// 0x0f
  OE  = 0x01,
// 0x66 0x0f
  O66 = 0x02,
// 0xf2 0x0f
  OF2 = 0x04,
// 0xf3 0x0f
  OF3 = 0x08,

  P1  = (OE),
  P2  = (O66 | OE),
  P4  = (OF3 | OE),
  P5  = (O66 | OF2),
  P6  = (OE  | O66 | OF3),
  P7  = (OE  | O66 | OF2 | OF3),
  P8  = (O66 | OF2 | OF3),

// 3-byte OP look-up table (0x38)

 OP3 = (OE | OF2 | O66),
 OP2 = (OE | OF2 | OF3),
 OP4 = (O66 | OF2 | OF3),

// 3-byte OP look-up table (0x3A)
 OP5 = (OE | O66),

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
 j1  = 0x12,
 j2  = 0x22,
 jc1 = 0x11,
 jc2 = 0x21
};

// 1-byte lookup table

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

// 2-byte OP look-up table
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

 uint64 disp;      // TODO: Arch based
 uint64 imm;       // TODO: Arch based
 uint64 target;    // TODO: Arch based // Target addr of relative addressing
 uint8  opcode;

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
         uint8 B : 1;  // Extends the 3-bit R/M field of the ModR/M byte or the Base field of the SIB byte, providing access to registers R8-R15 when used in the R/M or Base position. 
         uint8 X : 1;  // Extends the 3-bit Index field of the SIB byte, used for memory operands with a 4-bit index. 
         uint8 R : 1;  // Extends the 3-bit Reg field of the ModR/M byte, allowing for registers R8-R15 to be accessed. 
         uint8 W : 1;  // When set to 1, it indicates a 64-bit operand size. If 0, the operand size is determined by the instruction's opcode. 
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

 uint8 roles[15];   // parallel to instruction bytes

 uint8 vex[3];    // ???

 int size;
 int disp_len;
 int imm_len;

 uint16 set_prefix; // bit mask
 uint16 set_field;
 uint8  jcc_type;

 sint8 vex_cnt;       // Signed?

 vex_info vexi;
   
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
 memcpy(this->vex, &data[this->size], vex_size);
 this->vex_cnt += vex_size;
 this->size  += vex_size;

 this->opcode = data[this->size];
 this->roles[this->size++] = brOpcode;

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
 data += this->size;
 uint8 curr_byte = *data;
 uint8 next_byte = data[1];
 // 3-byte VEX prefix
 if((arch == X32 && curr_byte == 0xC4 && (next_byte >> 6) == 3) || (arch == X64 && curr_byte == 0xC4)) return 3;
 // 2-byte VEX prefix
   else if((arch == X32 && curr_byte == 0xC5 && (next_byte & 0x80)) || (arch == X64 && curr_byte == 0xC5)) return 2;
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
     if(arch == X32) return 4;
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
 if((val = modrm_table[this->opcode]))
  {
   this->set_field |= MODRM;
   if (val == X87_FPU) this->set_field |= FPU; 
   uint8 curr = data[this->size];  // *(start_data + this->size); 
   this->modrm.value = curr;
   this->size++;
   uint8 mod_val = this->modrm.bits.mod, rm_val = this->modrm.bits.rm;
  
   if(check_sib(this->modrm.bits.mod, this->modrm.bits.rm))
    {
     this->set_field |= SIB;    
     this->sib.value = data[this->size];  //(uint8_t)*(start_data + this->size);
     this->size++;
    
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
     memcpy(&this->disp, &data[this->size], this->disp_len);
     this->size    += this->disp_len;
     this->set_field |= DISP;
    }
  }

 this->imm_len = this->imm_size(imm_table[this->opcode], arch);
 if(this->imm_len)
  {
   this->set_field |= IMM;
   memcpy(&this->imm, &data[this->size], this->imm_len);
   this->size += this->imm_len;
  }

 uint16 value = 0;
 if(jcc_table != nullptr && (value = jcc_table[this->opcode]))       // !!!!!!!!!!!! TODO: Not just jmp - flag any control transfer (if needed at all)
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
   if(value & 0x10) this->target = (uint64)(data + sint8((uint8)this->imm) + this->size); // Overflow?   // RelAddrToAddr   // TODO: Recalc for every relative addressing
   // 4-byte
     else this->target = (uint64)(data + sint32((uint32)this->imm) + this->size);    // Overflow?
  }
}
//---------------------------------------------------------------------------
int Decode2B(enum supported_architecture arch, const uint8* data)
{
 this->set_prefix |= ESCAPE;
 uint8 curr        = data[this->size];   //*(data_src + this->size);

 if(curr == 0x38)
  {
   this->set_prefix |= OP3B;
   this->roles[this->size++] = brEscape | btEsc38;
   this->opcode = data[this->size]; 
   this->roles[this->size++] = brOpcode;
   this->decode_modrm(arch, data, modreg_3b_38, imm_byte_3b_38, nullptr);
   return this->size;
  }
 else if(curr == 0x3A)
  {
   this->set_prefix |= OP3B;
   this->roles[this->size++] = brEscape | btEsc3A;
   this->opcode = data[this->size]; 
   this->roles[this->size++] = brOpcode;
   this->decode_modrm(arch, data, modreg_3b_3A, imm_byte_3b_3A, nullptr);
   return this->size;
  }

 this->opcode = curr;
 this->roles[this->size++] = brOpcode;
 this->decode_modrm(arch, data, modrm_2b, imm_byte_2b, op2b_labels);
 return this->size;
}
//---------------------------------------------------------------------------
public:
int Decode(enum supported_architecture arch, const void* code)
{
 memset(this, 0, sizeof(*this));

 const uint8* data = (const uint8*)code;
 uint8 curr; // = *data;

/*
 while(X32_64_prefix[curr] & arch)
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
      this->set_prefix |= AS;   // Address-size override
      break;
     case 0xF0:   // CGPT
      this->set_prefix |= LOCK; 
      break;
     case 0xF2:   // CGPT
      this->set_prefix |= REPNE; 
      break;
     case 0xF3:   // CGPT
      this->set_prefix |= REPE;  
      break;
    }
  
   this->set_field                  |= PREFIX;
   this->prefixes[this->prefix_cnt]  = curr;
   this->prefix_cnt++;
   this->size++;
  
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
       return this->size;
      }
  
   curr = data[this->size];  //(uint8)*(data + this->size);
  }  */

for(;;) 
 {
  curr = data[this->size];
  if(this->size >= 15) return this->size;  // Too long!  // Max instr size is 15 bytes, even for all-prefix seqiences
  switch(curr) 
   {
    // --- Group 1: LOCK/REP prefixes ---
    case 0xF0: this->roles[this->size++] = brPrefix | SUB_LOCK;  this->set_prefix |= LOCK; continue;
    case 0xF2: this->roles[this->size++] = brPrefix | SUB_REPNE; this->set_prefix |= REPNE; continue;
    case 0xF3: this->roles[this->size++] = brPrefix | SUB_REPE;  this->set_prefix |= REPE; continue;

    // --- Group 2: Segment overrides ---
    case 0x2E: this->roles[this->size++] = brPrefix | SUB_SEG_CS; this->set_prefix |= CS; continue;
    case 0x36: this->roles[this->size++] = brPrefix | SUB_SEG_SS; this->set_prefix |= SS; continue;
    case 0x3E: this->roles[this->size++] = brPrefix | SUB_SEG_DS; this->set_prefix |= DS; continue;
    case 0x26: this->roles[this->size++] = brPrefix | SUB_SEG_ES; this->set_prefix |= ES; continue;
    case 0x64: this->roles[this->size++] = brPrefix | SUB_SEG_FS; this->set_prefix |= FS; continue;
    case 0x65: this->roles[this->size++] = brPrefix | SUB_SEG_GS; this->set_prefix |= GS; continue;

    // --- Group 3: Operand size ---
    case 0x66: this->roles[this->size++] = brPrefix | SUB_OPERAND; this->set_prefix |= OS; continue;

    // --- Group 4: Address size ---
    case 0x67: this->roles[this->size++] = brPrefix | SUB_ADDRESS;  this->set_prefix |= AS; continue;

    // --- REX prefixes (0x40–0x4F) ---
    default:
     if(this->size) this->set_field |= PREFIX;   // Have legacy prefixes
     if(arch == X64 && curr >= 0x40 && curr <= 0x4F)   // TODO: constexpr   // TODO 64-bit mode: IF OP == 90h and REX.B == 1, then the instruction is XCHG r8, rAX
      {
       this->roles[this->size++] = ROLE_REX; // subtype unused here
       this->rex.value  = curr;
       this->set_field |= REX;
       if(this->rex.bits.W) this->set_prefix |= OP64;  // record rex.W  // (curr & 0x08)    // TODO: Test for 'imm_size'
       continue;
      }
     break;
   }
 }

// --- Escapes: 0F, possibly with 38/3A ---
if(curr == 0x0F)
 {
  this->roles[this->size++] = brEscape | btEsc0F;
  this->Decode2B(arch, data);
  return this->size;
 }

 size_t vex_size = this->vex_size(arch, data);
 if(vex_size) this->vex_decode(arch, data, vex_size);
  else
   {
    this->opcode = curr;
    this->roles[this->size++] = brOpcode;
    this->decode_modrm(arch, data, modrm_1b, imm_byte_1b, op1b_labels);
   }

 return this->size;
}
//---------------------------------------------------------------------------
// Templated to accept not only pointers
template<typename T> inline static sint32 AddrToRelAddr(T CmdAddr, uint8 CmdLen, T TgtAddr){return -((CmdAddr + CmdLen) - TgtAddr);}       
template<typename T> inline static T      RelAddrToAddr(T CmdAddr, uint8 CmdLen, sint32 TgtOffset){return ((CmdAddr + CmdLen) + TgtOffset);}  

};
//---------------------------------------------------------------------------