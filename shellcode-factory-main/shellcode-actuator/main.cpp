#ifdef _WIN64
#ifdef _DEBUG
#include "../x64/Release/payload.hpp"
#else
#include "../x64/Release/payload.hpp"
#endif
#else
#ifdef _DEBUG
#include "../Debug/payload.hpp"
#else
#include "../Release/payload.hpp"
#endif
#endif // _WIN64

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
int main() 
{
    LoadLibraryA("user32.dll");
    LoadLibraryA("kernel32.dll");
    LoadLibraryA("KernelBase.dll");
    LoadLibraryA("msvcrt.dll");
    LoadLibraryA("gdi32.dll");

    auto shell_address = VirtualAlloc(0, sizeof(shellcode::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

     
    memcpy(shell_address, shellcode::payload, sizeof(shellcode::payload));


    int nInjectType = 0;


    //正常注入dll路径 这样写
    if (nInjectType == 0) {
        strcpy((char *)((ULONG_PTR)shell_address + shellcode::rva::szDllPath), "C:\\Users\\1\\Desktop\\COMMHLP64.dll");
    } else {
        //内存存入注入dll路径 这样写
        strcpy((char *)((ULONG_PTR)shell_address + shellcode::rva::szDllPath),
               "\\??\\C:\\Users\\1\\Desktop\\COMMHLP64.dll");
    }


     *(int*)((__int64)shell_address + shellcode::rva::bCreateRemote) = 0;
    *(int *)((__int64)shell_address + shellcode::rva::bMemoryInject) = nInjectType;
    *(__int64 *)((__int64)shell_address + shellcode::rva::NtdllBase) = (__int64)GetModuleHandleW(L"ntdll.dll");


     reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<char *>((__int64)shell_address+shellcode::rva::start))((void *)0x9999999);

     while (true) {
         Sleep(10000);
         
     }

    return 0;
}