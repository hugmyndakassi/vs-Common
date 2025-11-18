
#pragma once

//---------------------------------------------------------------------------
// https://www.righto.com/2023/07/undocumented-8086-instructions.html
// https://wiki.osdev.org/X86-64_Instruction_Encoding
// https://events.static.linuxfound.org/sites/events/files/slides/bpetkov-x86-hacks.pdf
// INFO: https://github.com/gdabah/distorm/

// A: default is same as the system
//
template<typename A=decltype(sizeof(void*)), bool NeedRoles=false> struct CIDEC   
{

using sint8  = char;
using uint8  = unsigned char;
using sint16 = short;
using uint16 = unsigned short;
using sint32 = int;
using uint32 = unsigned int;
using sint64 = long long;
using uint64 = unsigned long long;
using size_t = decltype(sizeof(void*));  // 'sizeof' returns size_t type

using arch_t = uint64;   // Depends on target CPU code

static constexpr const bool IsArch64 = (sizeof(A) == 8);

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


// Bits 4-7 = subtype (e.g. SEG=1, REP=2, LOCK=3, 0F escape=4, 38 escape=5…)
enum EByteRole : uint8 
{
 brNone      = 0x00,
 brPrefix    = 0x01,   // Legacy prefix
 brEscape    = 0x02,   // Legacy escape
 brOpcode    = 0x03,
 brModRM     = 0x04,
 brSIB       = 0x05,
 brDisp      = 0x06,   // A displacement (disp) is an offset added to a base address (often from a register like the instruction pointer) to calculate a final memory address. ('MOV EAX, [EBX + 8]', 'JMP label')
 brImm       = 0x07,   // An immediate value (imm) is a constant value embedded directly in the instruction itself. ('MOV AL, 5')
 brREX       = 0x08,   // REX prefixes (0x40–0x4F) (x64 only)
 brVEX       = 0x09    // VEX/EVEX escape
};

enum EByteType : uint8 
{
 btNone    = 0x00,

 // Prefix subtypes
 btLock    = 0x10,   // F0
 btRepNE   = 0x20,   // F2
 btRepE    = 0x30,   // F3
 btSOprd   = 0x40,   // 66   // Alt operand size
 btSAddr   = 0x50,   // 67   // Alt address size
 btSegCS   = 0x60,   // 2E
 btSegSS   = 0x70,   // 36
 btSegDS   = 0x80,   // 3E
 btSegES   = 0x90,   // 26
 btSegFS   = 0xA0,   // 64
 btSegGS   = 0xB0,   // 65

 // Value subtypes
 btValRel  = 0xC0    // Imm value is a relative address
};

enum ESegPfxType : uint8 
{
 spES = 0x26,
 spCS = 0x2E,
 spSS = 0x36,
 spDS = 0x3E,
 spFS = 0x64,
 spGS = 0x65
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
// The ModR/M byte is a 1-byte field in an instruction that describes the operands. It is divided into three parts: 
//   Mod field (2 bits): Determines the addressing mode for the operand. 
//   Reg/Opcode field (3 bits): Specifies a register or provides additional opcode bits. 
//   r/m field (3 bits): Specifies the register or helps define the addressing mode when combined with the Mod field. 
// 
// Mod Field:
//   00: Specifies a register-indirect mode with a 16-bit or 32-bit displacement, or a register-direct if the SIB byte is used. 
//   01: Specifies a memory operand with an 8-bit signed displacement. 
//   10: Specifies a memory operand with a 16-bit or 32-bit displacement. 
//   11: Indicates that the r/m field is a direct register operand (e.g., a specific register like EAX or ESI) rather than a memory address. 
//
// r/m Field:
//   When Mod = 11: The r/m field directly specifies a register operand. 
//   When Mod is not 11: The r/m field is part of the addressing-mode encoding, combining with the Mod field to define how a memory address is calculated. For example, in a 16-bit mode, specific r/m values like 000 could refer to [BX+SI]
//
// SIB byte may follow the ModR/M byte and enables more sophisticated ways to access memory, especially in 32-bit and 64-bit (x86-64) modes
// The SIB byte is divided into three fields: 
//   Scale (SS): A 2-bit field indicating the scaling factor for the index register.
//     00: * 1
//     01: * 2
//     10: * 4
//     11: * 8
//   Index (Index): A 3-bit field that specifies the index register (e.g., EBX).
//   Base (Base): A 3-bit field that specifies the base register (e.g., ESI).

// Consider the addressing mode [ebx*4 + esi + displacement]: 
//   The ModR/M byte would have a specific mode that indicates a SIB byte is needed (e.g., by the r/m field being 4). 
//   The SIB byte would be structured as follows:
//     Scale: 2 (since 2^2 = 4) 
//     Index: The code for EBX 
//     Base: The code for ESI 
//   A displacement would then follow the SIB byte to complete the full memory address. 

enum EInstrFeature: uint32 
{
 ifNone      = 0,

// Opcode flags. Should be here because they are mapped directly to opcode table to avoid 'switch'
 ifCond      = 0x00000001,   // Conditional (Jcc/CMOVcc/SETcc/LOOPcc/FPU/VEX) as part of an opcode
 ifJmpU      = 0x00000002,   // Jump instructions (Rel/Reg/Seg)
 ifJmpEx     = 0x00000004,   // Extra jumps (LOOP,JECXZ/JRCXZ)
 ifCall      = 0x00000008,   // Call instructions (Rel/Reg/Seg)

// Instruction fields (Opcode is implied)
 ifFldPrefix = 0x00000100,   // Legacy prefix field present
 ifFldEscape = 0x00000200,   // Legacy escape field (0x0F) present (2 byte opcode if not extended)  // MMX, SSE2, SSE3 // Historically, the ESC mnemonic used with the Intel 8087 (Now SSE)
 ifFldModRM  = 0x00000400, 
 ifFldDisp   = 0x00000800, 
 ifFldImm    = 0x00001000,   // JCC and Jmp Rel use it
 ifFldSIB    = 0x00002000,
 ifFldREX    = 0x00004000,   // REX prefixes (0x40–0x4F) (x64 only)
 ifFldVEX    = 0x00008000,   // ifFldXOP too?

// Legacy prefixes
 ifPfsSeg    = 0x00010000,   // Have a legacy segment prefix (stored in 'segment' field)
 ifPfxOS     = 0x00020000,   // 66  // Operand size override
 ifPfxAS     = 0x00040000,   // 67  // Address size override
 ifPfxREPNE  = 0x00080000,   // F2
 ifPfxREPE   = 0x00100000,   // F3
 ifPfxLOCK   = 0x00200000,   // F0
// ifPfxBrHint = 0x00400000,   // 2E, 3E : Taken/Not taken branch hints (Intel only, ignored on AMD)     // TODO
// ifPfxBrHint = 0x00800000,

// ifOpEsc_38  = 0x01000000,   // Extended escape field (0x38) (3 byte opcode) // SSE3,SSE4,SHA,AES,CRC
// ifOpEsc_3A  = 0x02000000,   // Extended escape field (0x3A) (3 byte opcode) // SSE3,SSE4,SHA,AES //  primarily used by Intel's SSE and later instruction set extensions.
 ifOprnd64   = 0x04000000,   // 64-bit operand (REX.W, X64 only)
 ifFPU       = 0x08000000,   // X87 FPU instruction // ??? // SSE, AVX ?

 //ifRelTgt    = 0x10000000,   // Have rel addressing target (jmp/mov)

 //ifVEX2b     = 0x10000000,   // >>> VexEscByte: 0xC5(2),0xC4(3),0x62(4)
 //ifVEX3b     = 0x20000000,
 //ifVEX4b     = 0x40000000,   // EVEX
};

enum ETblFlags: size_t
{
//ALL = (X32 | X64),

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

 jmp_ins = 1, // 0 - no jmp instr
 jmp_lng = 2, // 4 bytes rel
 jmp_cc  = 4, // conditional

 j1  = jmp_ins,                  // Jmp 1  
 j2  = jmp_ins|jmp_lng,          // Jmp 4
 jc1 = jmp_ins|jmp_cc,           // jcc 1
 jc2 = jmp_ins|jmp_cc|jmp_lng    // jcc 4
};

// 1-byte lookup table

static const inline uint8 modrm_1b[256] = {
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

static const inline uint8 imm_byte_1b[256] = {
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

// check if the OP is Jcc or JMP     // JECXZ [E3] ???  JECXZ/JRCXZ (0xE3)
static const inline uint8 op1b_labels[256] = {
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
static const inline uint8 modrm_2b[256] = {
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

static const inline uint8 imm_byte_2b[256] = {
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
static const inline uint8 op2b_labels[256] = {
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
static const inline uint8 modreg_3b_38[256] = {
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

static const inline uint8 imm_byte_3b_38[256] = {     // UNUSED - Should be skipped
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

static const inline uint8 modreg_3b_3A[256] = {
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

static const inline uint8 imm_byte_3b_3A[256] = {
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

// !!! NOTE: Those VEX tables are INCORRECT !!!!  // Fixed only for vzeroupper for now

// The tables below cover VEX-encoded opcodes in the 0x0F map (equivalent to legacy two-byte opcodes), 
//  excluding instructions that have no VEX encoding. Entries use the same flags as legacy tables (e.g. OE=ModRM present, O66/OF2/OF3 indicating required 0x66/F2/F3 prefix bits in legacy form). An entry of 0 means no ModRM or no VEX-coded instruction for that opcode. Immediate operand types use the same markers (b=8-bit, z/v=operand-size dependent, etc. – here only b is needed). These tables include all AVX/AVX2 VEX.128 and VEX.256 instructions (e.g. vector ALU ops, shuffles, blends, inserts, etc.) and omit legacy-only opcodes like system or branch instructions.

// VEX map 1 (0x0F) – ModRM requirements (OE=0x01 for ModRM, O66/OF2/OF3 for legacy prefix equivalence)
static const inline uint8 modrm_vex_0F[256] = {
//       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
/* 00 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 10 /  P7,P7,P7,P2,P2,P2,P6,P2, 0, 0, 0, 0, 0, 0, 0, 0,
/ 20 /  0, 0, 0, 0, 0, 0, 0, 0, P2,P2,P7,P2,P7,P7,P2,P2,
/ 30 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 40 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 50 /  P2,P7,P4,P4,P2,P2,P2,P2, P7,P7,P7,P6,P7,P7,P7,P7,
/ 60 /  P2,P2,P2,P2,P2,P2,P2,P2, P2,P2,P2,P2,O66,O66,P2,P2,
/ 70 /  P7,P1,P1,P1,P2,P2,P2, 0, 0, 0, 0, 0,P5,P5,P6,P6,
/ 80 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 90 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ A0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ B0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ C0 /  0, 0, P7, 0, 0, 0, P2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ D0 /  P5,P2,P2,P2,P2,P2,P8,P2, P2,P2,P2,P2,P2,P2,P2,P2,
/ E0 /  P2,P2,P2,P2,P2,P2,P8,P2, P2,P2,P2,P2,P2,P2,P2,P2,
/ F0 */  OF2,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// VEX map 1 (0x0F) – Immediate operand types (0 = none, b = 8-bit immediate)
static const inline uint8 imm_byte_vex_0F[256] = {
        //       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 10 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 20 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 40 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 50 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */  b, b, b, b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */  0, 0, 0, 0, b, 0, 0, 0, 0, 0, 0, 0, b, 0, 0, 0,
        /* B0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b, 0, 0, 0, 0, 0,
        /* C0 */  0, 0, b, 0, b, b, b, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


// The structure and flags mirror the legacy tables for 0x0F opcodes, updated to include VEX-only instructions (e.g. VPBLENDD at 0x3A02 with O66|OE for ModRM+66 prefix, imm8 control byte) 
// and to exclude non-VEX opcodes (e.g. system and branch instructions set to 0). Immediate bytes are marked for the same opcodes as in legacy SSE (e.g. 0x70–0x73 shuffles, 0xC2 comparisons) 
// and new AVX/AVX2 opcodes that require imm8 (like blends and inserts)

// Map 0x0F38 corresponds to legacy three-byte opcodes with leading 0F 38
// This includes packed integer and other SSE4, AES, PCLMULQDQ, and BMI/BMI2 instructions extended in AVX/AVX2. The tables below list ModRM and immediate info for VEX.128/256 versions of those instructions. (Most 0F38 opcodes have ModRM; none use an immediate in AVX/AVX2, so the immediate table is all zeros.)

// VEX map 2 (0x0F38) – ModRM table
static const inline uint8 modrm_vex_0F38[256] = {
//       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
/* 00 /  P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,P2,O66,O66,O66,O66,
/ 10 /  O66,0,0,O66,O66,O66,O66,O66,O66,O66,O66,0,O66,O66,O66,0,
/ 20 /  O66,O66,O66,O66,O66,O66,0,0,O66,O66,O66,O66,O66,O66,O66,O66,
/ 30 /  O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
/ 40 /  O66,O66, 0, 0, 0, O66,O66,O66, 0, 0, 0, 0, 0, 0, 0, 0,
/ 50 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 60 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 70 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 80 /  O66,O66,O66, 0, 0, 0, 0, 0, 0, 0, 0, 0,O66, 0,O66, 0,
/ 90 /  O66,O66,O66,O66, 0, 0,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
/ A0 /  0, 0, 0, 0, 0, 0,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
/ B0 /  0, 0, 0, 0, 0, 0,O66,O66,O66,O66,O66,O66,O66,O66,O66,O66,
/ C0 /  0, 0, 0, 0, 0, 0, 0, 0,O66,O66,O66,O66,O66,O66,O66,O66,
/ D0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,O66,O66,O66,O66,O66,
/ E0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,O66,O66,O66,O66,O66,
/ F0 */  OP3, OP3, OE, 0, 0, OP2, OP4, P7, 0, 0, 0, 0, 0, 0, 0, 0
};

// VEX map 2 (0x0F38) – Immediate bytes table (all zeros, no imm8 in AVX/AVX2 0F38 opcodes)
static const inline uint8 imm_byte_vex_0F38[256] = { 
        /* 00-FF */ 0 
};

// The modrm_vex_0F38 table is essentially identical to the legacy modreg_3b_38 table. All VEX 0F38 instructions use a ModRM byte (e.g. packed integer ops, AES rounds, PCLMULQDQ, and BMI2 bit manipulation ops like PDEP/PEXT which use OF2/OF3 flags to allow their F2h/F3h prefixes). 
// No 0F38-based AVX/AVX2 instruction takes an immediate operand, hence the immediate table is all zeros.

// Map 0x0F3A corresponds to opcodes with leading 0x0F 0x3A
// These are mostly SSE4.1/SSE4.2 instructions with an immediate byte (blends, dot-products, inserts/extracts, rounds, etc.), now extended via VEX for 128/256-bit (where applicable). The tables below give ModRM and immediate info for all AVX/AVX2 VEX-coded 0F3A opcodes. (Most require both a ModRM byte and an 8-bit immediate control.)

// VEX map 3 (0x0F3A) – ModRM table
static const inline uint8 modrm_vex_0F3A[256] = {
//       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
/* 00 /  O66, O66, O66, 0, O66, O66, O66, 0, O66, O66, O66, O66,O66 , O66, O66, OP5,
/ 10 /  0, 0, 0, 0, O66, O66, O66, O66, O66, O66, 0, 0, 0, O66, 0, 0,
/ 20 /  O66, O66, O66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 30 /  0, 0, 0, 0, 0, 0, 0, 0, O66, O66, 0, 0, 0, 0, 0, 0,
/ 40 /  O66, O66, O66, 0, O66, 0, O66, 0, 0, 0, O66, O66, O66, 0, 0, 0,
/ 50 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 60 /  O66, O66, O66, O66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 70 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 80 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ 90 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ A0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ B0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ C0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, O66, 0, 0, 0,
/ D0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, O66,
/ E0 /  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/ F0 */  OF2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// VEX map 3 (0x0F3A) – Immediate bytes table
static const inline uint8 imm_byte_vex_0F3A[256] = {
        //       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        /* 00 */  1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 10 */  0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0,
        /* 20 */  1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 30 */  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        /* 40 */  1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0,
        /* 50 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 60 */  1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 70 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 80 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 90 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F0 */  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


// These tables are based on the legacy modreg_3b_3A and imm_byte_3b_3A tables, covering SSE4.1/4.2 opcodes and their AVX equivalents.
//   For example, VROUNDPS (opcode 08h) and VINSERTPS (21h) both require a ModRM byte (O66|OE) and an 8-bit immediate (denoted by 1)
// Entries 60h–63h are the string compare instructions (VPCMPESTRM/I, VPCMPISTRM/I) which use O66 and an imm8 control byte
// New AVX2 opcodes like VPBLENDD (02h) and VINSERTI128 (38h) are included with the same pattern – ModRM present (here marked O66 since their legacy form used 66h) and an imm8 selector
// Opcode 0Fh (PALIGNR) uses OP5 (OE|O66) to allow either 66h or no prefix, as it encodes both byte and word variants (No entries beyond those listed have VEX-encoded forms, so they are zeroed out.)


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

 arch_t disp;      
 arch_t imm;       
 arch_t target;    // Target addr of relative addressing
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

 uint8 roles[16];   // Parallel to instruction bytes     // TODO: TSW
 uint8 escape;      // Legacy: 0F(single esc), 38, 3A. // VEX: C5, C4, 62
 uint8 segment;     // Legacy: Segment prefix 26, 2E, 36, 3E, 64, 65

 uint8 size;        // 0 - 15
 uint8 disp_len;    
 uint8 imm_len;
 uint8 esc_len;     // Size of escape sequence

 uint32 features;

 vex_info vexi;
   
private:

// rm == 4 means 'there’s a SIB byte' if and only if mod != 3.
// The mod < 3 part enforces 'we’re in memory addressing, not register-direct.'
// The rm == 4 part says 'this slot means SIB follows.'
static inline bool CheckSIB(uint8 mod, uint8 rm) { return (mod < 3) && (rm == 4); }
//---------------------------------------------------------------------------
// AMD: 0x8F - Three-byte XOP (but no one uses that anyway)
// This function not only determines size of VEX prefix but also checks if the inctruction could be a VEX instruction at all
// X32 need special handling: 
// The VEX prefix is similar but not identical in x32 and x64. 
// The primary difference arises from the need to support 64-bit registers and address space in x64, 
//  which required re-purposing instruction space previously used by legacy instructions like LDS and LES. 
// In x32, the VEX prefix's initial byte values (C4h and C5h) could clash with these legacy instructions, 
//  so the VEX encoding includes bit-inversion in its second byte to avoid this ambiguity. 
// In x64, this specific bit-inversion is not needed because those legacy instructions are not supported, 
//  but the VEX prefix remains distinct in its function and bit fields to accommodate the extended register set. 
//
static inline int SizeOfVEX(const uint8* data)   // TODO: EVEX ( 0x62, four bytes )
{
 uint8 CurrByte = *data;
 uint8 NextByte = data[1]; 
 if((CurrByte == 0xC5) && (NextByte & 0x80)) return 2;  // 2-byte VEX prefix
   else if((CurrByte == 0xC4) && (NextByte & 0x1F)) return 3;  // 3-byte VEX prefix      // m-mmmm is the disambiguator between VEX and the legacy LES, doing ((NextByte >> 6) == 3) is incorrect and will skip valid inctructions
 return 0;
}
//---------------------------------------------------------------------------
static inline int SizeOfDisp(uint8 mod, uint8 rm)
{
 switch(mod)
  {
   case 0:
    return (rm == 0x05) ? 4 : 0;  // indicates "displacement32 only" addressing (direct memory addressing with 32-bit address)
   case 1:
    return 1;  // indicates "register + displacement8" addressing mode
   case 2:
    return 4;  // indicates "register + displacement32" addressing mode  

   default: return 0;   // NOTE: SIB also may introduce Disp
  }
}
//---------------------------------------------------------------------------
inline int SizeOfImm(size_t val)
{
 switch(val)
  {
   case b:
    return 1;
   case v:
    if constexpr(IsArch64) { if(this->features & ifOprnd64)return 8; }
    return (this->features & ifPfxOS) ? 2 : 4;
   case z:
   case z1:
    return (this->features & ifPfxOS) ? 2 : 4;
   case p:
    if(this->features & ifPfxOS) return (IsArch64) ? 8 : 4;  // TODO: Shift size by arch OR *ifPfxOS* ???
    return 6;   // How?
   case w:
    return 2;
   case wb:
    return 3;   // TODO:  ENTER iw, ib
   case gr3b:
    return this->modrm.bits.reg ? 0 : 1;
   case gr3z:
    if(!this->modrm.bits.reg) return (this->features & ifPfxOS) ? 2 : 4;
    return 0;
  
   default: return 0;
  }
}
//---------------------------------------------------------------------------
inline void UpdateRole(uint8 at, uint8 role)   // TODO: Compile time optional
{
 if constexpr(NeedRoles) this->roles[at & 0x0F] |= role;     // 0x0F is for safety
}
//--------------------------------------------------------------------------- 
inline arch_t ReadValueWithRole(const uint8* data, uint8 at, uint8 len, uint8 role)
{
 arch_t res = 0;
 for(int idx=0;idx < len;at++,idx++)  // Little-Endian
  {
   arch_t val = data[at];
   res |= val << (idx << 3); // mul 8
   this->UpdateRole(at, role);
  }
 return res;
}
//--------------------------------------------------------------------------- 
inline void DecodeVEX(const uint8* data, uint8 vex_size)   // TODO: EVEX
{
 const uint8* pVex = &data[this->size];
 uint8 vpos    = this->size;
 this->esc_len = vex_size;
 this->size   += vex_size;
 this->opcode  = data[this->size];
 this->UpdateRole(this->size++, brOpcode);

 this->features |= ifFldVEX;
 if(vex_size == 2)  // 2-byte opcode
  {
   this->vexi.type = pVex[0];
   this->vexi.val5 = pVex[1];
   this->DecodeModRM(data, modrm_vex_0F[this->opcode], imm_byte_vex_0F[this->opcode], 0);
  }
   else if(vex_size == 3)  // 3-byte opcode
    {
     this->vexi.type = pVex[0];
     this->vexi.val4 = (uint16)this->ReadValueWithRole(data, vpos, 2, 0);  // !!!!!!!! What role ???????  
     sint8 index     = pVex[1] & 0x1F;   // m_mmmm  bits 0..4
     if(index)      // 'if(index==0)' - We should not crash!
      {
       if(index > 3)return;  // !!! invalid/unsupported VEX map 
   //    const uint8* imm_table[4]   = {nullptr, imm_byte_2b, imm_byte_3b_38, imm_byte_3b_3A};    // NOTE: Make sure that the compiler does not make it static
   //    const uint8* modrm_table[4] = {nullptr, modrm_2b, modreg_3b_38, modreg_3b_3A};
       const uint8* imm_table[4]   = {nullptr, imm_byte_vex_0F, imm_byte_vex_0F38, imm_byte_vex_0F3A};    // NOTE: Make sure that the compiler does not make it static
       const uint8* modrm_table[4] = {nullptr, modrm_vex_0F, modrm_vex_0F38,  modrm_vex_0F3A};
       this->DecodeModRM(data, modrm_table[index][this->opcode], imm_table[index][this->opcode], 0);   
      }
    }
 // TODO  XOP, 0x8F
}
//---------------------------------------------------------------------------
// In 64 bits the REX prefix might affect the index of the SIB byte. 
void DecodeModRM(const uint8* data, size_t modrm_type, size_t imm_type, size_t jcc_type)
{
 if(modrm_type)      // Just test for Zero
  {
   this->features |= ifFldModRM;
   if(modrm_type == X87_FPU) this->features |= ifFPU; 
   uint8 curr = data[this->size];
   this->UpdateRole(this->size++, brModRM);  
   this->modrm.value = curr;
   uint8 mod_val = this->modrm.bits.mod; 
   uint8 rm_val  = this->modrm.bits.rm;
  
   if(CheckSIB(this->modrm.bits.mod, this->modrm.bits.rm))    // When base == 5, use EBP as the base register !
    {
     this->features |= ifFldSIB;    
     this->sib.value = data[this->size];
     this->UpdateRole(this->size++, brSIB);    
     if(!mod_val && (this->sib.bits.base == 5))rm_val = 5;   // Special case: Mod==0 and SIB.base==5, the addressing is disp32 (or RIP relative) with no base register. // SizeOfDisp will handle the rest
    }
  
   this->disp_len = SizeOfDisp(mod_val, rm_val);
   if((this->disp_len | (this->features & ifFldDisp)))  // '|' not  '||' - single condition
    {
     this->disp      = this->ReadValueWithRole(data, this->size, this->disp_len, brDisp); // memcpy(&this->disp, &data[this->size], this->disp_len);   
     this->size     += this->disp_len;
     this->features |= ifFldDisp;       // May be a repeat but better than 'if()'
    }
  }

 this->imm_len = this->SizeOfImm(imm_type);
 if(this->imm_len)
  {
   this->imm       = this->ReadValueWithRole(data, this->size, this->imm_len, brImm);   // memcpy(&this->imm, &data[this->size], this->imm_len);
   this->size     += this->imm_len;
   this->features |= ifFldImm;
  }

 /*if(jcc_type)      
  {
   switch(jcc_type)     // !!!!!!!!!!!! TODO: Not just jmp - flag any control transfer (if needed at all)
    {
     case j1:
      this->features |= ifJmpU;
      break;
     case j2:
      this->features |= ifJmpU;
      break;
     case jc1:
      this->features |= ifJmpC;
      break;
     case jc2:
      this->features |= ifJmpC;
     default:
      break; // avoid compiler warnings
    }*/ 
   if(jcc_type & jmp_lng)this->target = (arch_t)(data + sint32((uint32)this->imm) + this->size);    // Overflow? 
     else this->target = (arch_t)(data + sint8((uint8)this->imm) + this->size); // Overflow?   // RelAddrToAddr   // TODO: Recalc for every relative addressing
  } 
}
//---------------------------------------------------------------------------
int Decode2B(const uint8* data)
{
 this->features |= ifFldEscape;
 uint8 curr      = data[this->size];   //*(data_src + this->size);

 if(curr == 0x38)
  {
   this->escape  = curr;
   this->esc_len = 2;
   this->UpdateRole(this->size++, brEscape);
   this->opcode  = data[this->size]; 
   this->UpdateRole(this->size++, brOpcode);
   this->DecodeModRM(data, modreg_3b_38[this->opcode], imm_byte_3b_38[this->opcode], 0);
   return this->size;
  }

 if(curr == 0x3A)
  {
   this->escape  = curr;
   this->esc_len = 2;
   this->UpdateRole(this->size++, brEscape);
   this->opcode  = data[this->size]; 
   this->UpdateRole(this->size++, brOpcode);
   this->DecodeModRM(data, modreg_3b_3A[this->opcode], imm_byte_3b_3A[this->opcode], 0);
   return this->size;
  }

 this->escape  = 0x0F; 
 this->esc_len = 1;
 this->opcode  = curr;
 this->UpdateRole(this->size++, brOpcode);
 this->DecodeModRM(data, modrm_2b[this->opcode], imm_byte_2b[this->opcode], op2b_labels[this->opcode]);
 return this->size;
}
//---------------------------------------------------------------------------
public:
int Decode(const void* code)
{
 memset(this, 0, sizeof(*this));
 const uint8* data = (const uint8*)code;
 uint8 curr; 

 for(;;) 
  {
   if(this->size >= 15) return this->size;  // Too long!  // Max instr size is 15 bytes, even for all-prefix seqiences
   curr = data[this->size];
   switch(curr) 
    {
     // --- Group 1: LOCK/REP prefixes ---
     case 0xF0: this->UpdateRole(this->size++, brPrefix | btLock);  this->features |= ifFldPrefix|ifPfxLOCK;  continue;
     case 0xF2: this->UpdateRole(this->size++, brPrefix | btRepNE); this->features |= ifFldPrefix|ifPfxREPNE; continue;
     case 0xF3: this->UpdateRole(this->size++, brPrefix | btRepE);  this->features |= ifFldPrefix|ifPfxREPE;  continue;
 
     // --- Group 2: Segment overrides ---
     case 0x2E: this->UpdateRole(this->size++, brPrefix | btSegCS); this->features |= ifFldPrefix|ifPfsSeg; continue;  // CS
     case 0x36: this->UpdateRole(this->size++, brPrefix | btSegSS); this->features |= ifFldPrefix|ifPfsSeg; continue;  // SS
     case 0x3E: this->UpdateRole(this->size++, brPrefix | btSegDS); this->features |= ifFldPrefix|ifPfsSeg; continue;  // DS
     case 0x26: this->UpdateRole(this->size++, brPrefix | btSegES); this->features |= ifFldPrefix|ifPfsSeg; continue;  // ES
     case 0x64: this->UpdateRole(this->size++, brPrefix | btSegFS); this->features |= ifFldPrefix|ifPfsSeg; continue;  // FS
     case 0x65: this->UpdateRole(this->size++, brPrefix | btSegGS); this->features |= ifFldPrefix|ifPfsSeg; continue;  // GS
 
     // --- Group 3: Operand size ---
     case 0x66: this->UpdateRole(this->size++, brPrefix | btSOprd); this->features |= ifFldPrefix|ifPfxOS; continue;  // immediates
 
     // --- Group 4: Address size ---
     case 0x67: this->UpdateRole(this->size++, brPrefix | btSAddr); this->features |= ifFldPrefix|ifPfxAS; continue;  // [addressing] // during JCXZ/JECXZ, the address size selects between the ECX and CX registers.
 
     // --- REX prefixes (0x40–0x4F) ---
     default:
  //    if(this->size) this->features |= ifFldPrefix;   // Have legacy prefixes
      if constexpr (IsArch64)
        if(curr >= 0x40 && curr <= 0x4F)   // TODO: constexpr   // TODO 64-bit mode: IF OP == 90h and REX.B == 1, then the instruction is XCHG r8, rAX
         {
          this->UpdateRole(this->size++, brREX); // subtype unused here
          this->rex.value  = curr;
          this->features |= ifFldREX;
          if(this->rex.bits.W) this->features |= ifOprnd64;  // record rex.W  // (curr & 0x08)    // TODO: Test for 'imm_size'
          continue;  // 'for' reacts to this
         }
      goto exit_loop;   // but 'break' here is consumed by 'switch'
    }
  }
exit_loop:

// --- Escapes: 0F, possibly with 38/3A ---
 if(curr == 0x0F)   // May have prefixes before it. Some CPUs may even consume a prefix after 0x0F
  {
   this->UpdateRole(this->size++, brEscape);
   this->Decode2B(data);
   return this->size;
  }

 size_t vex_size = 0;                                  
 if(!(this->features & (ifPfxOS|ifFldREX|ifPfxLOCK|ifPfxREPE|ifPfxREPNE)))vex_size = SizeOfVEX(&data[this->size]);  // Legacy prefixes like address-size override (0x67) and segment override (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65) are allowed and can precede a VEX  
 if(!vex_size) 
  {
   this->opcode = curr;
   this->UpdateRole(this->size++, brOpcode);
   this->DecodeModRM(data, modrm_1b[this->opcode], imm_byte_1b[this->opcode], op1b_labels[this->opcode]);
  }
   else this->DecodeVEX(data, vex_size);

 return this->size;
}
//---------------------------------------------------------------------------
// Templated to accept not only pointers
template<typename T> inline static sint32 AddrToRelAddr(T CmdAddr, uint8 CmdLen, T TgtAddr){return -((CmdAddr + CmdLen) - TgtAddr);}       
template<typename T> inline static T      RelAddrToAddr(T CmdAddr, uint8 CmdLen, sint32 TgtOffset){return ((CmdAddr + CmdLen) + TgtOffset);}  

};

template<int Flg=0> using IDEC32 = CIDEC<UINT32, Flg>;
template<int Flg=0> using IDEC64 = CIDEC<UINT64, Flg>;
template<int Flg=0> using IDEC   = CIDEC<decltype(sizeof(int)), Flg>;
//using IDEC   = TSW<IsArchX64, CHDE<SHDE64>, CHDE<SHDE32> >::T;
//---------------------------------------------------------------------------