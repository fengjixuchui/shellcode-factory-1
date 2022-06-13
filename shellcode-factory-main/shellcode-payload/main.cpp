#include "fun.h"
#include "shellcode.h"


#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()  
#define  STATUS_UNSUCCESSFUL 0xc0000001
//可以将优化开到最大，那全局变量最好使用 volatile 修饰

#define  DWORDX ULONG_PTR


SC_EXPORT_DATA(volatile int, bMemoryInject)        //是否启用内存注入
SC_EXPORT_DATA(volatile int, bCreateRemote)        //是否在shellcode中创建线程注入
SC_EXPORT_DATA(volatile __int64, NtdllBase)        // ntdll.dll 基地址
SC_EXPORT_DATA(volatile __int64, DllBase)          //被注入dll的基址
SC_EXPORT_DATA(volatile __int64, dwWantToAllcoate) //想要申请的地址
SC_EXPORT_DATA(volatile char, szDllPath[MAX_PATH]) //被注入dll的路径
// 使用全局和静态变量

LONG bOnceInject = true;

 PVOID AllocMemory(SIZE_T nSize);
//使用内嵌函数 这个东西只在本cpp起作用，不要写在.h里面 写在每个cpp的最开头部分
extern "C" {
#pragma function(memset)
void *__cdecl memset(void *dest, int value, size_t num) {
    __stosb(static_cast<unsigned char *>(dest), static_cast<unsigned char>(value), num);
    return dest;
}
#pragma function(memcpy)
void *__cdecl memcpy(void *dest, const void *src, size_t num) {
    __movsb(static_cast<unsigned char *>(dest), static_cast<const unsigned char *>(src), num);
    return dest;
}
}


t_vsnprintf_s                          My_vsnprintf_s = NULL;
t_sprintf_s                            My_sprintf_s = NULL;
t_LdrGetProcedureAddress               LdrGetProcedureAddress_ = NULL;
t_LdrLoadDll                           LdrLoadDll_= NULL;
t_RtlInitAnsiString                    RtlInitAnsiString_;
t_RtlAnsiStringToUnicodeString         RtlAnsiStringToUnicodeString_= NULL;
t_RtlFreeUnicodeString                 RtlFreeUnicodeString_= NULL;
t_ZwCreateSection                      ZwCreateSection_= NULL;
t_ZwMapViewOfSection                   ZwMapViewOfSection_= NULL;
t_ZwUnmapViewOfSection                 ZwUnmapViewOfSection_= NULL;
t_ZwCreateFile                         ZwCreateFile_= NULL;
t_RtlInitUnicodeString                 RtlInitUnicodeString_= NULL;
t_ZwQueryInformationFile               ZwQueryInformationFile_= NULL;
t_ZwClose                              ZwClose_= NULL;
_ZwCreateThreadEx                      ZwCreateThreadEx_            = NULL;
t_RtlAddFunctionTable                  RtlAddFunctionTable_       = NULL;
t_RtlImageDirectoryEntryToData         RtlImageDirectoryEntryToData_ = NULL;
t_RtlImageNtHeader                     RtlImageNtHeader_            = NULL;
t_ZwQueryVirtualMemory                 ZwQueryVirtualMemory_t      = NULL;

    //使用这个的函数的时候,请确保shellcode中的进程 必定加载 kernel32.dll
inline void ck_printf(const char *Format, ...) 
{
    char    Buf[MAX_PATH];
    memset(Buf, 0, MAX_PATH);

    if (My_vsnprintf_s) 
    {

        va_list Args;
        va_start(Args, Format);
        My_vsnprintf_s(Buf, _countof(Buf) - 1, _TRUNCATE, Format, Args);
        va_end(Args);
        LI_FN(OutputDebugStringA)(Buf);
    }
}


/*
 inline bool DoLogV(const char *fmt, va_list vargs) {

    if (!My_vsnprintf_s) {
         My_vsnprintf_s = (t_vsnprintf_s)LI_FN(GetProcAddress)(LI_FN(GetModuleHandleW)(L"ntdll.dll"), "_vsnprintf_s");
     }
     if (!My_sprintf_s) {
         My_sprintf_s = (t_sprintf_s)LI_FN(GetProcAddress)(LI_FN(GetModuleHandleW)(L"ntdll.dll"), "sprintf_s");
     }
     if (!My_sprintf_s || !My_vsnprintf_s) {
         return FALSE;
     }

     char varbuf[MAX_PATH] ;
     char message[MAX_PATH];
     memset(varbuf, 0, MAX_PATH);
     memset(message, 0, MAX_PATH);
     // Format messages
     My_vsnprintf_s(varbuf, _countof(varbuf), _TRUNCATE, fmt, vargs);
     My_sprintf_s(message, _countof(message), "%s", varbuf);
    
     LI_FN(SendMessageA)(g_hwnd, EM_REPLACESEL, 0, (LPARAM)message);

    return true;
}

 inline void send_to_notepad(const char *szText, ...) {
    if (g_hwnd) 
    {
    
        va_list alist;
        bool    result = false;

        va_start(alist, szText);
        result = DoLogV(szText, alist);
        va_end(alist);
    }
 }

 */


inline UINT AlignSize(UINT nSize, UINT nAlign) { return ((nSize + nAlign - 1) / nAlign * nAlign); }

 //为了使shellcode 兼容性最强（兼容驱动注入），只使用 Ntdll里面的所有函数
 bool initNtdllApi() 
 { 

     LdrGetProcedureAddress_  = (t_LdrGetProcedureAddress)GetProcAddressEx((PVOID)NtdllBase, "LdrGetProcedureAddress");
     LdrLoadDll_                   = (t_LdrLoadDll)GetProcAddressEx((PVOID)NtdllBase, "LdrLoadDll");
     RtlInitAnsiString_            = (t_RtlInitAnsiString)GetProcAddressEx((PVOID)NtdllBase, "RtlInitAnsiString");
     RtlAnsiStringToUnicodeString_ = (t_RtlAnsiStringToUnicodeString)GetProcAddressEx((PVOID)NtdllBase, "RtlAnsiStringToUnicodeString");
     RtlFreeUnicodeString_         = (t_RtlFreeUnicodeString)GetProcAddressEx((PVOID)NtdllBase, "RtlFreeUnicodeString");

     ZwUnmapViewOfSection_ = (t_ZwUnmapViewOfSection)GetProcAddressEx((PVOID)NtdllBase, "ZwUnmapViewOfSection");
     ZwMapViewOfSection_   = (t_ZwMapViewOfSection)GetProcAddressEx((PVOID)NtdllBase, "ZwMapViewOfSection");
     ZwCreateSection_      = (t_ZwCreateSection)GetProcAddressEx((PVOID)NtdllBase, "ZwCreateSection");

     ZwCreateFile_           = (t_ZwCreateFile)GetProcAddressEx((PVOID)NtdllBase, "ZwCreateFile");
     RtlInitUnicodeString_   = (t_RtlInitUnicodeString)GetProcAddressEx((PVOID)NtdllBase, "RtlInitUnicodeString");
     ZwQueryInformationFile_ = (t_ZwQueryInformationFile)GetProcAddressEx((PVOID)NtdllBase, "ZwQueryInformationFile");
     ZwClose_                = (t_ZwClose)GetProcAddressEx((PVOID)NtdllBase, "ZwClose");
     My_vsnprintf_s = (t_vsnprintf_s)GetProcAddressEx((PVOID)NtdllBase, "_vsnprintf_s");
     ZwCreateThreadEx_                = (_ZwCreateThreadEx)GetProcAddressEx((PVOID)NtdllBase, "ZwCreateThreadEx");
     RtlAddFunctionTable_                = (t_RtlAddFunctionTable)GetProcAddressEx((PVOID)NtdllBase, "RtlAddFunctionTable");
     RtlImageDirectoryEntryToData_                = (t_RtlImageDirectoryEntryToData)GetProcAddressEx((PVOID)NtdllBase, "RtlImageDirectoryEntryToData");
     RtlImageNtHeader_ = (t_RtlImageNtHeader)GetProcAddressEx((PVOID)NtdllBase, "RtlImageNtHeader");
     ZwQueryVirtualMemory_t = (t_ZwQueryVirtualMemory)GetProcAddressEx((PVOID)NtdllBase, "ZwQueryVirtualMemory");

     if (!LdrGetProcedureAddress_ || !LdrLoadDll_ || !RtlInitAnsiString_ || !RtlAnsiStringToUnicodeString_ || !RtlFreeUnicodeString_ || !ZwUnmapViewOfSection_ || !ZwMapViewOfSection_ || !ZwCreateSection_ ||
         !ZwCreateFile_ || !RtlInitUnicodeString_ || !ZwQueryInformationFile_ || !ZwClose_ || !My_vsnprintf_s ||!ZwCreateThreadEx_||
         !RtlAddFunctionTable_ ||!RtlImageDirectoryEntryToData_ ||!RtlImageNtHeader_ ||!ZwQueryVirtualMemory_t) 
     {
         return false;
     }




     return true;
 }


 bool NomalInject() 
 { 
     bool bRet = FALSE;

     UNICODE_STRING UnicodeString;
     ANSI_STRING    ansiStr;
     HANDLE         hDll    = 0;
     NTSTATUS       ntstaus = -1;

     RtlInitAnsiString_(&ansiStr, (PCSZ)szDllPath);
     ntstaus = RtlAnsiStringToUnicodeString_(&UnicodeString, &ansiStr, true);
     if (NT_SUCCESS(ntstaus)) {
         ntstaus = LdrLoadDll_(NULL, NULL, &UnicodeString, &hDll);
         if (!NT_SUCCESS(ntstaus)) {
             ck_printf("hzw:LdrLoadDll 失败:%x\n", ntstaus);
         } else 
         {
             bRet = TRUE;
             DllBase = (__int64)hDll;
         }

         RtlFreeUnicodeString_(&UnicodeString);
     } 

     return bRet;
 }


 PVOID GetDllFileBuffer() 
 {
     PVOID                     lpFileData = NULL;
     SIZE_T                    ViewSize   = 0;
     UNICODE_STRING            ufile_name;
     HANDLE                    hFileHanle = NULL;
     NTSTATUS                  status     = STATUS_UNSUCCESSFUL;
     IO_STATUS_BLOCK           IoStatusBlock;
     ANSI_STRING               ansiStr;
     HANDLE                    SectionHandle = 0;
     LARGE_INTEGER             MaximumSize;
     FILE_STANDARD_INFORMATION fbi;
     DWORD                     DataLength       = 0;
     OBJECT_ATTRIBUTES         ObjectAttributes = {
         sizeof(OBJECT_ATTRIBUTES), // Length
         NULL,                      // RootDirectory
         &ufile_name,               // ObjectName
         OBJ_CASE_INSENSITIVE,      // Attributes
         0,                         // SecurityDescriptor
         NULL,                      // SecurityQualityOfService
     };

     RtlInitAnsiString_(&ansiStr, (PCSZ)szDllPath);
     status = RtlAnsiStringToUnicodeString_(&ufile_name, &ansiStr, true);
     if (!NT_SUCCESS(status)) {

         lpFileData = NULL;
         goto __end;
     }

     
     status = ZwCreateFile_(&hFileHanle,
                            SYNCHRONIZE | GENERIC_READ,
                            &ObjectAttributes,
                            &IoStatusBlock,
                            0,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_READ,
                            FILE_OPEN,
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0);

     if (!NT_SUCCESS(status)) {

         ck_printf("hzw:ZwCreateFile_失败:%x \n", status);
        lpFileData = NULL;
         goto __end;
     }

     status = ZwQueryInformationFile_(
         hFileHanle, &IoStatusBlock, &fbi, sizeof(FILE_STANDARD_INFORMATION), 5 /*FileStandardInformation*/);

     if (!NT_SUCCESS(status)) {
         ck_printf("hzw:ZwQueryInformationFile_失败:%x \n", status);
         lpFileData = NULL;
         goto __end;
     }

     DataLength = fbi.EndOfFile.LowPart;

     MaximumSize.QuadPart = DataLength;

     ObjectAttributes.ObjectName = 0;
     status                      = ZwCreateSection_(
         &SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes, 0, PAGE_READONLY, SEC_COMMIT, hFileHanle);
     if (!NT_SUCCESS(status)) {
         ck_printf("hzw:ZwCreateSection_失败:%x \n", status);
        lpFileData = NULL;
         goto __end;
     }

     status            = ZwMapViewOfSection_(
         SectionHandle, NtCurrentProcess(), &lpFileData, 0, DataLength, NULL, &ViewSize, ViewUnmap, 0x400000, PAGE_READONLY);
     if (!NT_SUCCESS(status)) 
     {
         ck_printf("hzw:ZwMapViewOfSection_失败:%x \n", status);
        lpFileData = NULL;
         goto __end;
     }

 __end:

     if (SectionHandle) {
         ZwClose_(SectionHandle);
         SectionHandle = 0;
     }

     if (hFileHanle) {
         ZwClose_(hFileHanle);
         hFileHanle = 0;
     }

     RtlFreeUnicodeString_(&ufile_name);

     return lpFileData;
 }

 BOOL IsExecutableAddress(HANDLE hProcess, LPVOID pAddress) 
 {
     MEMORY_BASIC_INFORMATION mi = {0};
     SIZE_T                   ndwLength = 0;
     if (NT_SUCCESS(ZwQueryVirtualMemory_t(hProcess, pAddress, MemoryBasicInformation, &mi, sizeof(mi), &ndwLength))) 
     {
           return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
     }
     return FALSE;
   
 }
 PVOID AllocMemoryEx(SIZE_T nSize) 
 {
    PVOID         pAlloc         = NULL;
    int   nCnt   = 0;

    do 
    {
        pAlloc = AllocMemory(nSize);
        if (nCnt > 10) 
        {
            pAlloc = NULL;
            break;
        }
        nCnt++;
    } while (IsExecutableAddress(NtCurrentProcess(),pAlloc) == FALSE);

    return pAlloc;
  }


 PVOID AllocMemory(SIZE_T nSize) 
 {
     if (nSize == 0) {
         return NULL;
     }
     PVOID         pAlloc         = NULL;
     PVOID pMemoryAddress = (PVOID)dwWantToAllcoate;
     NTSTATUS      status = STATUS_UNSUCCESSFUL;
     LARGE_INTEGER MaximumSize;
     SIZE_T uSize         = nSize;
     MaximumSize.QuadPart = uSize;
     HANDLE SectionHandle = 0;
     status = ZwCreateSection_(&SectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
     if(NT_SUCCESS(status)) 
     {
     
         SIZE_T ViewSize = 0;
         status =ZwMapViewOfSection_(SectionHandle, NtCurrentProcess(), &pMemoryAddress, 0, uSize, NULL, &ViewSize,
                                        ViewUnmap, 0, PAGE_EXECUTE_READWRITE); 

         if (NT_SUCCESS(status)) 
         {
             pAlloc = pMemoryAddress;
         }

         ZwClose_(SectionHandle);
     }


     return pAlloc;
 }





 BOOL ImageFile(PVOID FileBuffer, PVOID *ImageModuleBase, DWORD &ImageSize) 
 {
     PIMAGE_DOS_HEADER     ImageDosHeader     = NULL;
     PIMAGE_NT_HEADERS     ImageNtHeaders     = NULL;
     PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;
     DWORD FileAlignment = 0, SectionAlignment = 0, NumberOfSections = 0, SizeOfImage = 0, SizeOfHeaders = 0;
     DWORD Index           = 0;
     PVOID ImageBase       = NULL;
     DWORD SizeOfNtHeaders = 0;

     if (!FileBuffer || !ImageModuleBase) {
         return FALSE;
     }



       ImageDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
     if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
         return FALSE;
     }

     ImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)FileBuffer + ImageDosHeader->e_lfanew); // PE头

     if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
         return FALSE;
     }

     FileAlignment    = ImageNtHeaders->OptionalHeader.FileAlignment;
     SectionAlignment = ImageNtHeaders->OptionalHeader.SectionAlignment;
     NumberOfSections = ImageNtHeaders->FileHeader.NumberOfSections;
     SizeOfImage      = ImageNtHeaders->OptionalHeader.SizeOfImage;
     SizeOfHeaders    = ImageNtHeaders->OptionalHeader.SizeOfHeaders;
     SizeOfImage      = AlignSize(SizeOfImage, SectionAlignment);

     ImageSize = SizeOfImage;

     ImageBase = AllocMemoryEx(SizeOfImage);
     if (ImageBase == NULL) {
         return FALSE;
     }
    ck_printf("hzw:alloc:%p \n", ImageBase);

     SizeOfNtHeaders = sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature) +
                       ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
     ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);

     
     /*
     for (Index = 0; Index < NumberOfSections; Index++) 
     {
         ImageSectionHeader[Index].SizeOfRawData = AlignSize(ImageSectionHeader[Index].SizeOfRawData, FileAlignment);
         ImageSectionHeader[Index].Misc.VirtualSize =
             AlignSize(ImageSectionHeader[Index].Misc.VirtualSize, SectionAlignment);
     }

     if (ImageSectionHeader[NumberOfSections - 1].VirtualAddress +
             ImageSectionHeader[NumberOfSections - 1].SizeOfRawData >
         SizeOfImage) {
         ImageSectionHeader[NumberOfSections - 1].SizeOfRawData =
             SizeOfImage - ImageSectionHeader[NumberOfSections - 1].VirtualAddress;
     }
     */

     memcpy(ImageBase, FileBuffer, SizeOfHeaders);

     for (Index = 0; Index < NumberOfSections; Index++) {
         DWORD   FileOffset  = ImageSectionHeader[Index].PointerToRawData;
         DWORD   Length      = AlignSize(ImageSectionHeader[Index].SizeOfRawData,FileAlignment);
         ULONG64 ImageOffset = AlignSize(ImageSectionHeader[Index].VirtualAddress,SectionAlignment);
         memcpy(&((PBYTE)ImageBase)[ImageOffset], &((PBYTE)FileBuffer)[FileOffset], Length);
     }
 
     *ImageModuleBase = ImageBase;


     return TRUE;
 }


 BOOL FixBaseRelocTable(PVOID pBuffer, ULONG_PTR dwLoadMemoryAddress) 
 {

     PIMAGE_NT_HEADERS pNTHeader = NULL;

     pNTHeader =  RtlImageNtHeader_(pBuffer);
     if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
         return FALSE;
     }

         if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0 &&
         pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {

         DWORDX  Delta = (DWORDX)dwLoadMemoryAddress - pNTHeader->OptionalHeader.ImageBase;
             DWORDX *pAddress = NULL;
         //注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
         PIMAGE_BASE_RELOCATION pLoc =
             (PIMAGE_BASE_RELOCATION)((DWORDX)pBuffer +
                                      pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                          .VirtualAddress);
         while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
         {
             WORD *pLocData = (WORD *)((DWORDX)pLoc + sizeof(IMAGE_BASE_RELOCATION));
             //计算本节需要修正的重定位项（地址）的数目
             int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
             for (int i = 0; i < NumberOfReloc; i++) {
                 if ((DWORDX)(pLocData[i] & 0xF000) == 0x00003000 ||
                     (DWORDX)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
                 {
                     // 举例：
                     // pLoc->VirtualAddress = 0×1000;
                     // pLocData[i] = 0×313E; 表示本节偏移地址0×13E处需要修正
                     // 因此 pAddress = 基地址 + 0×113E
                     // 里面的内容是 A1 ( 0c d4 02 10) 汇编代码是： mov eax , [1002d40c]
                     // 需要修正1002d40c这个地址
                     pAddress = (DWORDX *)((DWORDX)pBuffer + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                     *pAddress += Delta;
                 }
             }
             //转移到下一个节进行处理
             pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pLoc + pLoc->SizeOfBlock);
         }
         /***********************************************************************/
     }
     pNTHeader->OptionalHeader.ImageBase = (DWORDX)dwLoadMemoryAddress;
   

     return TRUE;
 }



 BOOL FixImportTable(PVOID pBuffer, ULONG_PTR dwLoadMemoryAddress) {
     PIMAGE_NT_HEADERS pNtHeaders = NULL;
     ANSI_STRING       ansiStr;
     UNICODE_STRING    UnicodeString;


     pNtHeaders = RtlImageNtHeader_(pBuffer);
     if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
         return FALSE;
     }

     ULONG_PTR Offset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

     PIMAGE_IMPORT_DESCRIPTOR pID     = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pBuffer + Offset);
     PIMAGE_IMPORT_BY_NAME    pByName = NULL;

     while (pID->Characteristics != 0) {

         PIMAGE_THUNK_DATA pRealIAT     = (PIMAGE_THUNK_DATA)((ULONG_PTR)pBuffer + pID->FirstThunk);
         PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pBuffer + pID->OriginalFirstThunk);
         //获取dll的名字
         char * pName = (char *)((ULONG_PTR)pBuffer + pID->Name);
         HANDLE hDll  = 0;

         RtlInitAnsiString_(&ansiStr, pName);

         RtlAnsiStringToUnicodeString_(&UnicodeString, &ansiStr, true);

         LdrLoadDll_(NULL, NULL, &UnicodeString, &hDll);

         RtlFreeUnicodeString_(&UnicodeString);

         if (hDll == NULL) {

             return FALSE;
         }

         //获取DLL中每个导出函数的地址，填入IAT
         //每个IAT结构是 ：
         // union { PBYTE ForwarderString;
         // PDWORDX Function;
         // DWORDX Ordinal;
         // PIMAGE_IMPORT_BY_NAME AddressOfData;
         // } u1;
         // 长度是一个DWORDX ，正好容纳一个地址。
         for (ULONG i = 0;; i++) {
             if (pOriginalIAT[i].u1.Function == 0)
                 break;
             FARPROC lpFunction = NULL;
             if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) //这里的值给出的是导出序号
             {
                 if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal)) {

                     LdrGetProcedureAddress_(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
                 }
             } else //按照名字导入
             {
                 //获取此IAT项所描述的函数名称
                 pByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pBuffer + (ULONG_PTR)(pOriginalIAT[i].u1.AddressOfData));
                 if ((char *)pByName->Name) {
                     RtlInitAnsiString_(&ansiStr, (char *)pByName->Name);

                     LdrGetProcedureAddress_(hDll, &ansiStr, 0, &lpFunction);
                 }
             }

             //标记***********

             if (lpFunction != NULL) //找到了！
                 pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
             else {
                 return FALSE;
             }
         }

         // move to next
         pID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
     }
   
     return FixBaseRelocTable(pBuffer, dwLoadMemoryAddress);
 }





 bool MemoryInject() 
 {
     bool bRet = FALSE;
    

      PVOID                     lpFileData = NULL;

     lpFileData = GetDllFileBuffer();
     ck_printf("hzw:lpFileData:%p \n", lpFileData);
     if (lpFileData) 
     {
         PVOID ImageBase = NULL;
         DWORD dwImageSize = 0;
         NTSTATUS status      = STATUS_UNSUCCESSFUL;
         
          if (ImageFile(lpFileData, &ImageBase, dwImageSize)) {
              if (FixImportTable(ImageBase, (ULONG_PTR)ImageBase)) {

                  ULONG                          dirSize = 0;
                  BOOL                           bSeh    = FALSE;
                  _PIMAGE_RUNTIME_FUNCTION_ENTRY pExpTable =
                      (_PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlImageDirectoryEntryToData_(
                          ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &dirSize);

                  bSeh = RtlAddFunctionTable_(pExpTable, (ULONG_PTR)(dirSize / sizeof(_IMAGE_RUNTIME_FUNCTION_ENTRY)),
                                              (DWORD64)ImageBase);
                  ck_printf("hzw:是否支持:%d \n", bSeh);

                  PIMAGE_NT_HEADERS pNTHeader = RtlImageNtHeader_(ImageBase);
                  ;

                  t_ProcDllMain pDllMain =
                      (t_ProcDllMain)(pNTHeader->OptionalHeader.AddressOfEntryPoint + (DWORDX)ImageBase);
                  pDllMain(0, DLL_PROCESS_ATTACH, ImageBase);
                  DllBase = (__int64)ImageBase;
                  bRet = true;

              } else {
                  ck_printf("hzw:FixImportTable failed \n");
              }
          }

          status = ZwUnmapViewOfSection_(NtCurrentProcess(), lpFileData);
          if (!NT_SUCCESS(status)) {
              ck_printf("hzw:ZwUnmapViewOfSection_ failed:%x \n", status);
          }

     }

     return bRet;
 }

 bool start_inject_work() 
 {
     bool n = FALSE;
     if (bMemoryInject == false) {
         n = NomalInject();

     } else 
     {
         n = MemoryInject();
     }
     return n;
 }


 SC_EXPORT DWORD __fastcall start(PVOID pArg) 
{

     DWORD n = -1;

     if (InterlockedCompareExchange((LONG*)&bOnceInject,0,1) == 1 ) 
     {
   
         if (!NtdllBase || !initNtdllApi()) {
             ck_printf("hzw:初始化失败:ntdll:%p 传入参数:%p\n", NtdllBase, pArg);
             return n;
         }

         ck_printf("hzw:bMemoryInject:%d bCreateRemote:%d  ntdll:%p 传入参数:%p dll:%s\n",
                   bMemoryInject,
                   bCreateRemote,
                   NtdllBase,
                   pArg,
                   szDllPath);

         if (bCreateRemote == FALSE) 
         {
             ck_printf("hzw:非创建线程注入\n");
             n = start_inject_work();
         } else {
             ck_printf("hzw:创建线程注入\n");
             HANDLE   hThreadHanle = 0;
             NTSTATUS ntstats      = STATUS_UNSUCCESSFUL;
             ntstats               = ZwCreateThreadEx_(&hThreadHanle,
                                         THREAD_ALL_ACCESS,
                                         NULL,
                                         NtCurrentProcess(),
                                         (LPTHREAD_START_ROUTINE)start_inject_work,
                                         pArg,
                                         0,
                                         0,
                                         0,
                                         0,
                                         NULL);
             if (!NT_SUCCESS(ntstats)) {
                 ck_printf("hzw:ZwCreateThreadEx_失败:%d 传入参数:%p\n", ntstats);
             }

             if (hThreadHanle) {
                 ZwClose_(hThreadHanle);
             }
         }

     }
     ck_printf("hzw:加载DLLBase:%p \n", DllBase);
     return n;

}









ULONG64 GetProcAddressEx(PVOID BaseAddress, char *lpFunctionName) 
{

    PIMAGE_DOS_HEADER       pDosHdr  = (PIMAGE_DOS_HEADER)BaseAddress;
    PIMAGE_NT_HEADERS32     pNtHdr32 = NULL;
    PIMAGE_NT_HEADERS64     pNtHdr64 = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport  = NULL;
    ULONG                   expSize  = 0;
    ULONG_PTR               pAddress = 0;
    PUSHORT                 pAddressOfOrds;
    PULONG                  pAddressOfNames;
    PULONG                  pAddressOfFuncs;
    ULONG                   i;

    if (BaseAddress == NULL)
        return 0;

    /// Not a PE file
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);

    // Not a PE file
    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    // 64 bit image
    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                                .VirtualAddress +
                                            (ULONG_PTR)BaseAddress);
        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // 32 bit image
    else {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                                .VirtualAddress +
                                            (ULONG_PTR)BaseAddress);
        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    pAddressOfOrds  = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
    pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)BaseAddress);
    pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)BaseAddress);

    for (i = 0; i < pExport->NumberOfFunctions; ++i) {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName    = NULL;

        // Find by index
        if ((ULONG_PTR)lpFunctionName <= 0xFFFF) {
            OrdIndex = (USHORT)i;
        }
        // Find by name
        else if ((ULONG_PTR)lpFunctionName > 0xFFFF && i < pExport->NumberOfNames) {
            pName    = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)BaseAddress);
            OrdIndex = pAddressOfOrds[i];
        }
        // Weird params
        else
            return 0;

        if (((ULONG_PTR)lpFunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)lpFunctionName) == OrdIndex + pExport->Base) ||
            ((ULONG_PTR)lpFunctionName > 0xFFFF && strcmp_(pName, (char *)(PCTSTR)lpFunctionName) == 0)) {
            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)BaseAddress;

            // Check forwarded export
            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize) {
                return 0;
            }

            break;
        }
    }
    return (ULONG_PTR)pAddress;
}