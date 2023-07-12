
#pragma once

//------------------------------------------------------------------------------------------------------------
private:
// TODO: Pack these fields in a structure and scramble them (OPTIONAL)
struct SSINF
{
 void*            STInfo;  // Pointer to stack frame info, received from kernel  // PEB on windows?
 achar**          CLArgs;  // Points to ARGV array  // Not split on windows!
 achar**          EVVars;  // Points to EVAR array (cannot cache this pointer?)
 achar**          AuxInf;  // Auxilary vector (Not for MacOS or Windows)     // LINUX/BSD: ELF::SAuxVecRec*   // MacOS: Apple info (Additional Name=Value list)
 uint32           UTCOffs; // In seconds

 void*  TheModBase;
 size_t TheModSize;
 achar  SysDrive[8];
 bool   HaveLoader;

// Exe path (Even if this module is a DLL)
// Current directory(at startup)   // Required?
// Working dir (Not have to be same as current dir)
// Temp path
} static inline fwsinf = {};
//------------------------------------------------------------------------------------------------------------

#if defined(SYS_UNIX) || defined(SYS_ANDROID)  //|| defined(_SYS_BSD)
static ELF::SAuxVecRec* GetAuxVRec(size_t Type)
{
 for(ELF::SAuxVecRec* Rec=(ELF::SAuxVecRec*)fwsinf.AuxInf;Rec->type != ELF::AT_NULL;Rec++)
  {
   if(Rec->type == Type)return Rec;
  }
 return nullptr;
}
#endif

//------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------
static _finline size_t GetArgC(void){return (size_t)fwsinf.CLArgs[-1];}   // On Windows should be always 1? // Be careful with access to SInfo using casts. Clang may optimize out ALL! code because of it
static _finline const achar** GetArgV(void){return (const achar**)fwsinf.CLArgs;}
static _finline const achar** GetEnvP(void){return (const achar**)fwsinf.EVVars;}
static int UpdateTZOffsUTC(sint64 CurTimeUTC)
{
 int df = NAPI::open("/etc/localtime",PX::O_RDONLY,0);
//  LOGMSG("TZFILE open: %i",df);
 if(df < 0)return df;
 uint8 TmpBuf[2048];       // Should be enough for V1 header
 sint rlen = NAPI::read(df, &TmpBuf, sizeof(TmpBuf));
 NAPI::close(df);
 if(rlen <= 44)return PX::ENODATA;     // sizeof(SHdrTZ)
 sint32 offs = STZF::GetTimeZoneOffset(&TmpBuf,CurTimeUTC);
//    LOGMSG("TZFILE offs: %i",offs);
 if(offs < 0)return PX::EINVAL;
 fwsinf.UTCOffs = offs;
 return 0;
}
public:
//------------------------------------------------------------------------------------------------------------
static _finline PX::fdsc_t GetStdIn(void)  {return PX::STDIN; }  // 0
static _finline PX::fdsc_t GetStdOut(void) {return PX::STDOUT;}  // 1
static _finline PX::fdsc_t GetStdErr(void) {return PX::STDERR;}  // 2
//------------------------------------------------------------------------------------------------------------
static _finline sint32 GetTZOffsUTC(void){return fwsinf.UTCOffs;}
static _finline bool   IsLoadedByLdr(void) {return fwsinf.HaveLoader;}    // OnWindows, Any DLL that loaded by loader
static _finline bool   IsDynamicLib(void) {return false;}
//------------------------------------------------------------------------------------------------------------
// %rdi, %rsi, %rdx, %rcx, %r8 and %r9
// DescrPtr must be set to 'ELF Auxiliary Vectors' (Stack pointer at ELF entry point)
//
/*
argv[0] is not guaranteed to be the executable path, it just happens to be most of the time. It can be a relative path from the current
working directory, or just the filename of your program if your program is in PATH, or an absolute path to your program, or the name a
symlink that points to your program file, maybe there are even more possibilities. It's whatever you typed in the shell to run your program.
*/
// Copies a next param to user`s buffer
// A spawner process is responsible for ARGV
// Quotes are stripped by the shell and quoted args are kept intact
// NOTE: Do not expect the return value to be an argument index!
static uint GetCmdLineArg(sint& AOffs, achar* DstBuf, uint BufLen=-1)
{
 if(DstBuf)*DstBuf = 0;
 if(AOffs < 0)return -3;     // Already finished
 if(AOffs >= (sint)GetArgC())return -2;    // No such arg
 const achar* CurArg = GetArgV()[AOffs++];
 uint  ArgLen = 0;
 if(!DstBuf)
  {
   while(CurArg[ArgLen])ArgLen++;
   return ArgLen+1;   // +Space for terminating 0
  }
 for(;CurArg[ArgLen] && (ArgLen < BufLen);ArgLen++)DstBuf[ArgLen] = CurArg[ArgLen];
 DstBuf[ArgLen] = 0;
 if(AOffs >= (sint)GetArgC())AOffs = -1;
 return ArgLen;
}
//------------------------------------------------------------------------------------------------------------
static sint GetEnvVar(const achar* Name, achar* DstBuf, size_t BufCCnt)
{
 const achar** vars = GetEnvP();
 bool Unnamed = !Name || !*Name;
 for(;const achar* evar = *vars;vars++)
  {
   int spos = NSTR::CharOffsetIC(evar, '=');
   if(spos < 0)continue;  // No separator!
   if((!spos && Unnamed) || NSTR::IsStrEqualSC(Name, evar, spos))return NSTR::StrCopy(DstBuf, &evar[spos+1], BufCCnt);
  }
 return -1;
}
//------------------------------------------------------------------------------------------------------------
// AppleInfo on MacOS
static sint GetSysInfo(uint InfoID, void* DstBuf, size_t BufSize)
{
 //GetAuxVRec(size_t Type)
 return -1;
}
//------------------------------------------------------------------------------------------------------------
//
static _finline void* GetModuleBase(void)
{
 return fwsinf.TheModBase;
}
//------------------------------------------------------------------------------------------------------------
//
static _finline size_t GetModuleSize(void)
{
 return fwsinf.TheModSize;
}
//------------------------------------------------------------------------------------------------------------
// Returns full path to current module and its name in UTF8
static size_t _finline GetModulePath(achar* DstBuf, size_t BufSize=-1)
{
 sint aoffs = 0;
 return GetCmdLineArg(aoffs, DstBuf, BufSize);       // Will work for now
}
//------------------------------------------------------------------------------------------------------------
static sint InitStartupInfo(void* StkFrame=nullptr, void* ArgA=nullptr, void* ArgB=nullptr, void* ArgC=nullptr)
{
 DBGDBG("StkFrame=%p, ArgA=%p, ArgB=%p, ArgC=%p",StkFrame,ArgA,ArgB,ArgC);
 IFDBG{ DBGDBG("Stk[0]=%p, Stk[1]=%p, Stk[2]=%p, Stk[3]=%p, Stk[4]=%p", ((void**)StkFrame)[0], ((void**)StkFrame)[1], ((void**)StkFrame)[2], ((void**)StkFrame)[3], ((void**)StkFrame)[4]); }

  // LOGMSG("StkFrame=%p, ArgA=%p, ArgB=%p, ArgC=%p",StkFrame,ArgA,ArgB,ArgC);
 //  LOGMSG("Stk[0]=%p, Stk[1]=%p, Stk[2]=%p, Stk[3]=%p, Stk[4]=%p", ((void**)StkFrame)[0], ((void**)StkFrame)[1], ((void**)StkFrame)[2], ((void**)StkFrame)[3], ((void**)StkFrame)[4]);
 /*if(!APtr)  // Try to get AUXV from '/proc/self/auxv'
  {
   return -1;
  }
   // It may not be known if we are in a shared library
*/
 /*if(StkFrame) // NOTE: C++ Clang enforces the stack frame to contain some EntryPoints`s saved registers
  {
//   TODO: detect if this is a DLL loaded by loader, or if the EXE started from loader
   if constexpr (IsArchX64)
    {
     if constexpr(IsCpuARM)StkFrame = &((void**)StkFrame)[4]; // ARM 64: Stores X19,X29,X30 and aligns to 16   // __builtin_frame_address does not return the frame address as it was at the function entry
       else StkFrame = &((void**)StkFrame)[1];  // Untested  // No ret addr on stack, only stack frame ptr

    }
     else
      {
       if constexpr(IsCpuARM)StkFrame = &((void**)StkFrame)[2]; // ARM 32: PUSH {R11,LR} - 0: RetAddr, 1:StackFramePtr   // __builtin_frame_address does not return the frame address as it was at the function entry
         else StkFrame = &((void**)StkFrame)[1];  // No ret addr on stack, only stack frame ptr
      }
  }*/
 if(StkFrame)
  {
   // TODO: If loaded by loader then on X86 there are return address on stack?
   // More complicated!

   fwsinf.STInfo = StkFrame;
   uint ArgNum  = ((size_t*)StkFrame)[0];           // Number of command line arguments
   fwsinf.CLArgs = (char**)&((void**)StkFrame)[1];   // Array of cammond line arguments
   fwsinf.EVVars = &fwsinf.CLArgs[ArgNum+1];          // Array of environment variables
   void*  APtr  = nullptr;
   char** Args  = fwsinf.EVVars;
   uint ParIdx  = 0;
   do{APtr=Args[ParIdx++];}while(APtr);  // Skip until AUX vector
   fwsinf.AuxInf = &Args[ParIdx];
  }

 //PX::timezone tz = {};
 //if(!NAPI::gettimeofday(nullptr, &tz))fwsinf.UTCOffs = tz.minuteswest;
 PX::timeval tv = {};
 if(!NAPI::gettimeofday(&tv, nullptr))UpdateTZOffsUTC(tv.sec);    // Log any errors?
 //LOGMSG("TZFILE offs: %i",tz.minuteswest);

  // DbgLogStartupInfo();
 DBGDBG("STInfo=%p, CLArgs=%p, EVVars=%p, AuxInf=%p",fwsinf.STInfo,fwsinf.CLArgs,fwsinf.EVVars,fwsinf.AuxInf);
 return 0;
}
//============================================================================================================
static void DbgLogStartupInfo(void)
{
 if(!fwsinf.STInfo)return;
 // Log command line arguments
 if(fwsinf.CLArgs)
  {
   void*   APtr = nullptr;
   achar** Args = fwsinf.CLArgs;
   uint  ParIdx = 0;
   LOGDBG("CArguments: ");
   for(uint idx=0;(APtr=Args[ParIdx++]);idx++)
    {
     LOGDBG("  Arg %u: %s",idx,APtr);
    }
  }
 // Log environment variables
 if(fwsinf.EVVars)
  {
   void*   APtr = nullptr;
   achar** Args = fwsinf.EVVars;
   uint  ParIdx = 0;
   LOGDBG("EVariables: ");
   while((APtr=Args[ParIdx++]))
    {
//LOGDBG("  VA: %p",APtr);
     LOGDBG("  Var: %s",APtr);
    }
  }
 // Log auxilary vector
 if(fwsinf.AuxInf)
  {
   LOGDBG("AVariables : ");
   if constexpr(IsSysLinux)
    {
     for(ELF::SAuxVecRec* Rec=(ELF::SAuxVecRec*)fwsinf.AuxInf;Rec->type != ELF::AT_NULL;Rec++)
      {
       LOGDBG("  Aux: Type=%.3u, Value=%p",Rec->type, (void*)Rec->val);
      }
    }
   else if constexpr(IsSysMacOS)
    {
     void*  APtr = nullptr;
     char** Args = fwsinf.AuxInf;
     uint ParIdx = 0;
     while((APtr=Args[ParIdx++]))
      {
       LOGDBG("  AVar: %s",APtr);
      }
    }
  }
 DBGDBG("Done!");
}
//------------------------------------------------------------------------------------------------------------
/*
ABI specific?

ArmX64:
 EntryPoint:
  +00 NewSp
  +08
  +10 X29     GETSTKFRAME()
  +18 X30
  +20 X19
  +28
  +30 OrigSP  ArgNum (Stack before Entry)
*/

/* ====================== LINUX/BSD ======================
Stack layout from startup code:
  argc
  argv pointers
  NULL that ends argv[]
  environment pointers
  NULL that ends envp[]
  ELF Auxiliary Table
  argv strings
  environment strings
  program name
  NULL
*/

// =========================== MACH-O system entry frame =======================
/*
 * C runtime startup for interface to the dynamic linker.
 * This is the same as the entry point in crt0.o with the addition of the
 * address of the mach header passed as an extra first argument.
 *
 * Kernel sets up stack frame to look like:
 *
 *  | STRING AREA | 'executable_path=' + All strings from fields below
 *  +-------------+
 *  |      0      |
*   +-------------+
 *  |  apple[n]   |
 *  +-------------+
 *         :
 *  +-------------+
 *  |  apple[0]   |  // Name=value or nulls
 *  +-------------+
 *  |      0      |
 *  +-------------+
 *  |    env[n]   |
 *  +-------------+
 *         :
 *         :
 *  +-------------+
 *  |    env[0]   |  // Name=value
 *  +-------------+
 *  |      0      |
 *  +-------------+
 *  | arg[argc-1] |
 *  +-------------+
 *         :
 *         :
 *  +-------------+
 *  |    arg[0]   |   // Value (split command line)
 *  +-------------+
 *  |     argc    |   // on x86-64 RSP  points directly to 'argc', not to some return address
 *  +-------------+
 *. |      mh     | <--- [NOT TRUE?]sp, address of where the a.out's file offset 0 is in memory (MACH-O header)
 *  +-------------+
 *
 *  Where arg[i] and env[i] point into the STRING AREA
 */

// NOTE: Looks like it is impossible to create a valid MACH-O executable(not dylib) which does not references dyld and receives control directly from Kernel

/*
Apple`s loader loads and run all initial functions from dynamically linked libraries. Due to this, we can create functions that run before the main binary is started.


Executable 0x2 (mh_execute/mh_executable) - Is not linked. Is used to create a launchable program - Application, App extension - Widget. Application target is a default setting
Bundle 0x8 (mh_bundle .bundle) - loadable bundle - run time linked. iOS now supports only Testing Bundle target where it is a default setting to generate a Loadable bundle.
System -> Testing Bundle -> tested binary. A location of Testing Bundle will be depended on target, static or dynamic binary...
Dynamic Library 0x6 (mh_dylib .dylib or none) - Load/run time linked.
With Framework target - Dynamic Library is a default setting to generate a Dynamic framework
Static Library(staticlib .a) - Compilation time(build time) linked.
With Static Library target - Static Library is a default setting to generate a Static library
With Framework target - Static Library to generate a Static framework
Relocatable Object File 0x1 (mh_object .o) - Compilation time(build time) linked. It is the simplest form. It is a basement to create executable, static or dynamic format. Relocatable because variables and functions don't have any specific address


 =========================== ELF system AUXV =======================
// http://articles.manugarg.com/aboutelfauxiliaryvectors.html

position            content                     size (bytes) + comment
  ------------------------------------------------------------------------
  stack pointer ->  [ argc = number of args ]     4
                    [ argv[0] (pointer) ]         4   (program name)
                    [ argv[1] (pointer) ]         4
                    [ argv[..] (pointer) ]        4 * x
                    [ argv[n - 1] (pointer) ]     4
                    [ argv[n] (pointer) ]         4   (= NULL)

                    [ envp[0] (pointer) ]         4
                    [ envp[1] (pointer) ]         4
                    [ envp[..] (pointer) ]        4
                    [ envp[term] (pointer) ]      4   (= NULL)

                    [ auxv[0] (Elf32_auxv_t) ]    8
                    [ auxv[1] (Elf32_auxv_t) ]    8
                    [ auxv[..] (Elf32_auxv_t) ]   8
                    [ auxv[term] (Elf32_auxv_t) ] 8   (= AT_NULL vector)

                    [ padding ]                   0 - 16

                    [ argument ASCIIZ strings ]   >= 0
                    [ environment ASCIIZ str. ]   >= 0

  (0xbffffffc)      [ end marker ]                4   (= NULL)

  (0xc0000000)      < bottom of stack >           0   (virtual)


//============================================================================================
X64: At start:
Stack is aligned to 8
rsp[0]: Ret addr to 'dyld'


@loader_path

ld:
     -execute    The default. Produce a mach-o main executable that has file
                 type MH_EXECUTE.

     -dylib      Produce a mach-o shared library that has file type MH_DYLIB.

     -bundle     Produce a mach-o bundle that has file type MH_BUNDLE.

     -dynamic    The default. Implied by -dylib, -bundle, or -execute

     -static     Produces a mach-o file that does not use the dyld. Only used
                 building the kernel.
*/



