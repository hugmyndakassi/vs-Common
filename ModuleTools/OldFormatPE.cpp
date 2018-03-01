//---------------------------------------------------------------------------
#pragma hdrstop

#include "OldFormatPE.h"
//#include <MemWork.h>

//---------------------------------------------------------------------------
void FastZeroMemory(PVOID Addr, UINT Size){memset(Addr,0,Size);}
void FastMoveMemory(PVOID DstBlk, PVOID SrcBlk, DWORD Length){memmove(DstBlk,SrcBlk,Length);}

bool _stdcall IsValidPEHeader(PVOID Header)
{
 DOS_HEADER *DosHdr;
 WIN_HEADER *WinHdr;

 DosHdr = (DOS_HEADER*)Header;
 if(IsBadReadPtr((PVOID)DosHdr,sizeof(DOS_HEADER))||(DosHdr->FlagMZ != SIGN_MZ))return false;
 WinHdr = (WIN_HEADER*)&(((BYTE*)Header)[DosHdr->OffsetHeaderPE]);
 if(IsBadReadPtr((PVOID)WinHdr,sizeof(WIN_HEADER))||(WinHdr->FlagPE != SIGN_PE))return false;

 // TO DO: All checks !!!
 return true;
}
//---------------------------------------------------------------------------
PDWORD _stdcall GetEntryPointOffset(PVOID Header)
{
 DOS_HEADER *DosHdr;
 WIN_HEADER *WinHdr;

 DosHdr = (DOS_HEADER*)Header;
 WinHdr = (WIN_HEADER*)&(((BYTE*)Header)[DosHdr->OffsetHeaderPE]);
 return &WinHdr->OptionalHeader.EntryPointRVA;
}
//---------------------------------------------------------------------------
UINT _stdcall GetEntryPoint(PVOID Header)
{
 return GetEntryPointOffset(Header)[0]; 
}
//---------------------------------------------------------------------------
void _stdcall SetEntryPoint(PVOID Header, UINT Entry)
{
 GetEntryPointOffset(Header)[0] = Entry;
}
//---------------------------------------------------------------------------
DWORD _stdcall RvaToFileOffset(PVOID ModuleInMem, DWORD ModuleRva, SECTION_HEADER **RvaInSection)
{
 DOS_HEADER     *DOSHeader;
 WIN_HEADER     *WINHeader;
 SECTION_HEADER *CurSection;

 if(!IsValidPEHeader(ModuleInMem))return 0;
 DOSHeader   = (DOS_HEADER*)ModuleInMem;
 WINHeader   = (WIN_HEADER*)&((BYTE*)ModuleInMem)[DOSHeader->OffsetHeaderPE];
 CurSection  = (SECTION_HEADER*)&((BYTE*)ModuleInMem)[(DOSHeader->OffsetHeaderPE+sizeof(WIN_HEADER))];
 for(int ctr = 0;ctr < WINHeader->FileHeader.SectionsNumber;ctr++,CurSection++)
  {
   if((ModuleRva >= CurSection->SectionRva)&&(ModuleRva < (CurSection->SectionRva+CurSection->PhysicalSize)))
	{
	 // Offset within current section
	 if(RvaInSection)(*RvaInSection) = CurSection;
	 return (CurSection->PhysicalOffset+(ModuleRva-CurSection->SectionRva));
	}
  }
 return ModuleRva;
}
//---------------------------------------------------------------------------
DWORD _stdcall RvaToFileOffsetF(HANDLE hModuleFile, DWORD ModuleRva, SECTION_HEADER *RvaInSection)
{
 DOS_HEADER     DOSHeader;
 WIN_HEADER     WINHeader;
 SECTION_HEADER TmpSection;
 DWORD          Result;

 if(RvaInSection != NULL)FastZeroMemory(RvaInSection,sizeof(SECTION_HEADER));
 SetFilePointer(hModuleFile,0,NULL,FILE_BEGIN);
 ReadFile(hModuleFile,&DOSHeader,sizeof(DOS_HEADER),&Result,NULL);
 if(Result != sizeof(DOS_HEADER))return 0;   //  cannot read file
 SetFilePointer(hModuleFile,DOSHeader.OffsetHeaderPE,NULL,FILE_BEGIN);
 ReadFile(hModuleFile,&WINHeader,sizeof(WIN_HEADER),&Result,NULL);
 if(Result != sizeof(WIN_HEADER))return 0;   //  cannot read file

 for(int ctr = 0;ctr < WINHeader.FileHeader.SectionsNumber;ctr++)
  {
   ReadFile(hModuleFile,&TmpSection,sizeof(SECTION_HEADER),&Result,NULL);
   if(Result != sizeof(SECTION_HEADER))return 0;   //  cannot read file
   if((ModuleRva >= TmpSection.SectionRva)&&(ModuleRva < (TmpSection.SectionRva+TmpSection.PhysicalSize)))
	{
	 // Offset within current section
	 if(RvaInSection != NULL)FastMoveMemory(RvaInSection,&TmpSection,sizeof(SECTION_HEADER));
	 return (TmpSection.PhysicalOffset+(ModuleRva-TmpSection.SectionRva));
	}
  }
 return ModuleRva;
}
//---------------------------------------------------------------------------
DWORD _stdcall FileOffsetToRva(PVOID ModuleInMem, DWORD FileOffset, SECTION_HEADER **OffsetInSection)
{
 DOS_HEADER     *DOSHeader;
 WIN_HEADER     *WINHeader;
 SECTION_HEADER *CurSection;

 if(!IsValidPEHeader(ModuleInMem))return 0;
 DOSHeader   = (DOS_HEADER*)ModuleInMem;
 WINHeader   = (WIN_HEADER*)&((BYTE*)ModuleInMem)[DOSHeader->OffsetHeaderPE];
 CurSection  = (SECTION_HEADER*)&((BYTE*)ModuleInMem)[(DOSHeader->OffsetHeaderPE+sizeof(WIN_HEADER))];
 for(int ctr = 0;ctr < WINHeader->FileHeader.SectionsNumber;ctr++,CurSection++)
  {
   if((FileOffset >= CurSection->PhysicalOffset)&&(FileOffset < (CurSection->PhysicalOffset+CurSection->PhysicalSize)))
	{
	 // Offset within current section
	 if(OffsetInSection)(*OffsetInSection) = CurSection;
	 return ((FileOffset-CurSection->PhysicalOffset)+CurSection->SectionRva);
	}
  }
 return FileOffset;
}
//---------------------------------------------------------------------------
DWORD _stdcall FileOffsetToRvaF(HANDLE hModuleFile, DWORD FileOffset, SECTION_HEADER *OffsetInSection)
{
 DOS_HEADER     DOSHeader;
 WIN_HEADER     WINHeader;
 SECTION_HEADER TmpSection;
 DWORD          Result;

 if(OffsetInSection != NULL)FastZeroMemory(OffsetInSection,sizeof(SECTION_HEADER));
 SetFilePointer(hModuleFile,0,NULL,FILE_BEGIN);
 ReadFile(hModuleFile,&DOSHeader,sizeof(DOS_HEADER),&Result,NULL);
 if(Result != sizeof(DOS_HEADER))return 0;   //  cannot read file
 SetFilePointer(hModuleFile,DOSHeader.OffsetHeaderPE,NULL,FILE_BEGIN);
 ReadFile(hModuleFile,&WINHeader,sizeof(WIN_HEADER),&Result,NULL);
 if(Result != sizeof(WIN_HEADER))return 0;   //  cannot read file

 for(int ctr = 0;ctr < WINHeader.FileHeader.SectionsNumber;ctr++)
  {
   ReadFile(hModuleFile,&TmpSection,sizeof(SECTION_HEADER),&Result,NULL);
   if(Result != sizeof(SECTION_HEADER))return 0;   //  cannot read file
   if((FileOffset >= TmpSection.PhysicalOffset)&&(FileOffset < (TmpSection.PhysicalOffset+TmpSection.PhysicalSize)))
	{
	 // Offset within current section
	 if(OffsetInSection != NULL)FastMoveMemory(OffsetInSection,&TmpSection,sizeof(SECTION_HEADER));
	 return ((FileOffset-TmpSection.PhysicalOffset)+TmpSection.SectionRva);
	}
  }
 return FileOffset;
}
//---------------------------------------------------------------------------
// Returns true if the address in some section of the module
bool _stdcall GetSectionForAddress(HMODULE ModulePtr, PVOID Address, SECTION_HEADER **Section)
{
 DOS_HEADER     *DOSHeader;
 WIN_HEADER     *WINHeader;
 SECTION_HEADER *CurSection;

 if(!IsValidPEHeader(ModulePtr))return false;
 DOSHeader   = (DOS_HEADER*)ModulePtr;
 WINHeader   = (WIN_HEADER*)&((BYTE*)ModulePtr)[DOSHeader->OffsetHeaderPE];
 CurSection  = (SECTION_HEADER*)&((BYTE*)ModulePtr)[(DOSHeader->OffsetHeaderPE+sizeof(WIN_HEADER))];
 for(int ctr = 0;ctr < WINHeader->FileHeader.SectionsNumber;ctr++,CurSection++)
  {
   if((((PBYTE)ModulePtr+CurSection->SectionRva) <= (PBYTE)Address)&&(((PBYTE)ModulePtr+CurSection->SectionRva+CurSection->VirtualSize) > (PBYTE)Address))    
	{
	 // The address is within current section
	 if(Section)(*Section) = CurSection;
	 return true;
	}
  }
 return false;
}
//---------------------------------------------------------------------------
