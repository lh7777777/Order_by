#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_STRCPY_DEFINED__
#define OCALL_STRCPY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_strcpy, (char* DeStr, char* SoStr, size_t DeLen, size_t SoLen));
#endif
#ifndef OCALL_SPRINTF_DEFINED__
#define OCALL_SPRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sprintf, (char* pt, int ipt));
#endif
#ifndef OCALL_INPUT_DEFINED__
#define OCALL_INPUT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_input, (int input));
#endif
#ifndef OCALL_OPENDN1SGX_DEFINED__
#define OCALL_OPENDN1SGX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendn1sgx, (void));
#endif
#ifndef OCALL_READDN1SGX_DEFINED__
#define OCALL_READDN1SGX_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdn1sgx, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSEDN1SGX_DEFINED__
#define OCALL_CLOSEDN1SGX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedn1sgx, (void));
#endif
#ifndef OCALL_OPENDN2SGX_DEFINED__
#define OCALL_OPENDN2SGX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendn2sgx, (void));
#endif
#ifndef OCALL_READDN2SGX_DEFINED__
#define OCALL_READDN2SGX_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdn2sgx, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSEDN2SGX_DEFINED__
#define OCALL_CLOSEDN2SGX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedn2sgx, (void));
#endif
#ifndef OCALL_OPENDN3SGX_DEFINED__
#define OCALL_OPENDN3SGX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendn3sgx, (void));
#endif
#ifndef OCALL_READDN3SGX_DEFINED__
#define OCALL_READDN3SGX_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdn3sgx, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSEDN3SGX_DEFINED__
#define OCALL_CLOSEDN3SGX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedn3sgx, (void));
#endif
#ifndef OCALL_OPENSGXDN1_DEFINED__
#define OCALL_OPENSGXDN1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opensgxdn1, (void));
#endif
#ifndef OCALL_WRITESGXDN1_DEFINED__
#define OCALL_WRITESGXDN1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writesgxdn1, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSESGXDN1_DEFINED__
#define OCALL_CLOSESGXDN1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closesgxdn1, (void));
#endif
#ifndef OCALL_OPENSGXDN2_DEFINED__
#define OCALL_OPENSGXDN2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opensgxdn2, (void));
#endif
#ifndef OCALL_WRITESGXDN2_DEFINED__
#define OCALL_WRITESGXDN2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writesgxdn2, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSESGXDN2_DEFINED__
#define OCALL_CLOSESGXDN2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closesgxdn2, (void));
#endif
#ifndef OCALL_OPENSGXDN3_DEFINED__
#define OCALL_OPENSGXDN3_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opensgxdn3, (void));
#endif
#ifndef OCALL_WRITESGXDN3_DEFINED__
#define OCALL_WRITESGXDN3_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writesgxdn3, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSESGXDN3_DEFINED__
#define OCALL_CLOSESGXDN3_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closesgxdn3, (void));
#endif
#ifndef OCALL_OPENOUTFILE1_DEFINED__
#define OCALL_OPENOUTFILE1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openoutfile1, (void));
#endif
#ifndef OCALL_WRITEOUTFILE1_DEFINED__
#define OCALL_WRITEOUTFILE1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writeoutfile1, (int m1));
#endif
#ifndef OCALL_CLOSEOUTFILE1_DEFINED__
#define OCALL_CLOSEOUTFILE1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closeoutfile1, (void));
#endif
#ifndef OCALL_OPENOUTFILE2_DEFINED__
#define OCALL_OPENOUTFILE2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openoutfile2, (void));
#endif
#ifndef OCALL_WRITEOUTFILE2_DEFINED__
#define OCALL_WRITEOUTFILE2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writeoutfile2, (int m2));
#endif
#ifndef OCALL_CLOSEOUTFILE2_DEFINED__
#define OCALL_CLOSEOUTFILE2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closeoutfile2, (void));
#endif
#ifndef OCALL_OPENOUTFILE3_DEFINED__
#define OCALL_OPENOUTFILE3_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openoutfile3, (void));
#endif
#ifndef OCALL_WRITEOUTFILE3_DEFINED__
#define OCALL_WRITEOUTFILE3_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writeoutfile3, (int m3));
#endif
#ifndef OCALL_CLOSEOUTFILE3_DEFINED__
#define OCALL_CLOSEOUTFILE3_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closeoutfile3, (void));
#endif
#ifndef OCALL_OPENDN1LABEL_DEFINED__
#define OCALL_OPENDN1LABEL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendn1label, (void));
#endif
#ifndef OCALL_READDN1LABEL_DEFINED__
#define OCALL_READDN1LABEL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdn1label, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSEDN1LABEL_DEFINED__
#define OCALL_CLOSEDN1LABEL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedn1label, (void));
#endif
#ifndef OCALL_OPENDN2LABEL_DEFINED__
#define OCALL_OPENDN2LABEL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendn2label, (void));
#endif
#ifndef OCALL_READDN2LABEL_DEFINED__
#define OCALL_READDN2LABEL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdn2label, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSEDN2LABEL_DEFINED__
#define OCALL_CLOSEDN2LABEL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedn2label, (void));
#endif
#ifndef OCALL_OPENDN3LABEL_DEFINED__
#define OCALL_OPENDN3LABEL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendn3label, (void));
#endif
#ifndef OCALL_READDN3LABEL_DEFINED__
#define OCALL_READDN3LABEL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdn3label, (unsigned char* fres));
#endif
#ifndef OCALL_CLOSEDN3LABEL_DEFINED__
#define OCALL_CLOSEDN3LABEL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedn3label, (void));
#endif
#ifndef OCALL_OPENOUTPUTFILE_DEFINED__
#define OCALL_OPENOUTPUTFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openoutputfile, (void));
#endif
#ifndef OCALL_WRITEOUTPUTFILE_DEFINED__
#define OCALL_WRITEOUTPUTFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writeoutputfile, (int m));
#endif
#ifndef OCALL_WRITEOUTPUTFILE2_DEFINED__
#define OCALL_WRITEOUTPUTFILE2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writeoutputfile2, (char* m));
#endif
#ifndef OCALL_CLOSEOUTPUTFILE_DEFINED__
#define OCALL_CLOSEOUTPUTFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closeoutputfile, (void));
#endif
#ifndef OCALL_STARTCLOCK1_DEFINED__
#define OCALL_STARTCLOCK1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_startclock1, (void));
#endif
#ifndef OCALL_ENDCLOCK1_DEFINED__
#define OCALL_ENDCLOCK1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_endclock1, (void));
#endif
#ifndef OCALL_TIME1_DEFINED__
#define OCALL_TIME1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time1, (void));
#endif
#ifndef OCALL_STARTCLOCK_DEFINED__
#define OCALL_STARTCLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_startclock, (void));
#endif
#ifndef OCALL_ENDCLOCK_DEFINED__
#define OCALL_ENDCLOCK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_endclock, (void));
#endif
#ifndef OCALL_TIME_DEFINED__
#define OCALL_TIME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time, (void));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid, int mm, char* ssk);
sgx_status_t ecall_update(sgx_enclave_id_t eid, int dnc);
sgx_status_t ecall_orderby(sgx_enclave_id_t eid);
sgx_status_t ecall_output(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
