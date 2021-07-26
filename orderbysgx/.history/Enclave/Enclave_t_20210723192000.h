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
void ecall_orderby(void);
void ecall_output(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_strcpy(char* DeStr, char* SoStr, size_t DeLen, size_t SoLen);
sgx_status_t SGX_CDECL ocall_sprintf(char* pt, int ipt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
