#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init(int mm, char* ssk);
void ecall_update(int dnc);
void ecall_orderby(void);
void ecall_output(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_strcpy(char* DeStr, char* SoStr, size_t DeLen, size_t SoLen);
sgx_status_t SGX_CDECL ocall_sprintf(char* pt, int ipt);
sgx_status_t SGX_CDECL ocall_input(int input);
sgx_status_t SGX_CDECL ocall_opendn1sgx(void);
sgx_status_t SGX_CDECL ocall_readdn1sgx(int* retval, unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closedn1sgx(void);
sgx_status_t SGX_CDECL ocall_opendn2sgx(void);
sgx_status_t SGX_CDECL ocall_readdn2sgx(int* retval, unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closedn2sgx(void);
sgx_status_t SGX_CDECL ocall_opendn3sgx(void);
sgx_status_t SGX_CDECL ocall_readdn3sgx(int* retval, unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closedn3sgx(void);
sgx_status_t SGX_CDECL ocall_opensgxdn1(void);
sgx_status_t SGX_CDECL ocall_writesgxdn1(unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closesgxdn1(void);
sgx_status_t SGX_CDECL ocall_opensgxdn2(void);
sgx_status_t SGX_CDECL ocall_writesgxdn2(unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closesgxdn2(void);
sgx_status_t SGX_CDECL ocall_opensgxdn3(void);
sgx_status_t SGX_CDECL ocall_writesgxdn3(unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closesgxdn3(void);
sgx_status_t SGX_CDECL ocall_openoutfile1(void);
sgx_status_t SGX_CDECL ocall_writeoutfile1(int m1);
sgx_status_t SGX_CDECL ocall_closeoutfile1(void);
sgx_status_t SGX_CDECL ocall_openoutfile2(void);
sgx_status_t SGX_CDECL ocall_writeoutfile2(int m2);
sgx_status_t SGX_CDECL ocall_closeoutfile2(void);
sgx_status_t SGX_CDECL ocall_openoutfile3(void);
sgx_status_t SGX_CDECL ocall_writeoutfile3(int m3);
sgx_status_t SGX_CDECL ocall_closeoutfile3(void);
sgx_status_t SGX_CDECL ocall_opendn1label(void);
sgx_status_t SGX_CDECL ocall_readdn1label(int* retval, unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closedn1label(void);
sgx_status_t SGX_CDECL ocall_opendn2label(void);
sgx_status_t SGX_CDECL ocall_readdn2label(int* retval, unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closedn2label(void);
sgx_status_t SGX_CDECL ocall_opendn3label(void);
sgx_status_t SGX_CDECL ocall_readdn3label(int* retval, unsigned char* fres);
sgx_status_t SGX_CDECL ocall_closedn3label(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
