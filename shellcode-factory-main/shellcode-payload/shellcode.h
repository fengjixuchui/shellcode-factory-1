#pragma once
#include "lazy_importer.hpp"
#ifndef _M_IX86
#include "xorstr.hpp"
#else
#define xorstr_(str) (str)
#endif //

#include <Windows.h>
#include <cstdio>
#define SC_EXPORT extern "C" _declspec(dllexport)
#define SC_EXPORT_DATA(type, data)                                                                                     \
    extern "C" _declspec(dllexport) type data;                                                                         \
    type                                 data;

template <typename T, size_t N>
constexpr size_t ArrNum(T (&A)[N]) {
    return N;
}

ULONG64 GetProcAddressEx(PVOID BaseAddress, char *lpFunctionName);

inline int strcmp_(const char* dest, const char* source) {
    if (!dest || !source)
        return -1;
    while (*dest && *source &&(*dest == *source)) 
    {
        dest++;
        source++;
    }
    return *dest - *source;
}



