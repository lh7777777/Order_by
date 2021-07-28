#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_t {
	int ms_mm;
	char* ms_ssk;
} ms_ecall_init_t;

typedef struct ms_ecall_update_t {
	int ms_dnc;
} ms_ecall_update_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_strcpy_t {
	char* ms_DeStr;
	char* ms_SoStr;
	size_t ms_DeLen;
	size_t ms_SoLen;
} ms_ocall_strcpy_t;

typedef struct ms_ocall_sprintf_t {
	char* ms_pt;
	int ms_ipt;
} ms_ocall_sprintf_t;

typedef struct ms_ocall_input_t {
	int ms_input;
} ms_ocall_input_t;

typedef struct ms_ocall_readdn1sgx_t {
	int ms_retval;
	unsigned char* ms_fres;
} ms_ocall_readdn1sgx_t;

typedef struct ms_ocall_readdn2sgx_t {
	int ms_retval;
	unsigned char* ms_fres;
} ms_ocall_readdn2sgx_t;

typedef struct ms_ocall_readdn3sgx_t {
	int ms_retval;
	unsigned char* ms_fres;
} ms_ocall_readdn3sgx_t;

typedef struct ms_ocall_writesgxdn1_t {
	unsigned char* ms_fres;
} ms_ocall_writesgxdn1_t;

typedef struct ms_ocall_writesgxdn2_t {
	unsigned char* ms_fres;
} ms_ocall_writesgxdn2_t;

typedef struct ms_ocall_writesgxdn3_t {
	unsigned char* ms_fres;
} ms_ocall_writesgxdn3_t;

typedef struct ms_ocall_writeoutfile1_t {
	int ms_m1;
} ms_ocall_writeoutfile1_t;

typedef struct ms_ocall_writeoutfile2_t {
	int ms_m2;
} ms_ocall_writeoutfile2_t;

typedef struct ms_ocall_writeoutfile3_t {
	int ms_m3;
} ms_ocall_writeoutfile3_t;

typedef struct ms_ocall_readdn1label_t {
	int ms_retval;
	unsigned char* ms_fres;
} ms_ocall_readdn1label_t;

typedef struct ms_ocall_readdn2label_t {
	int ms_retval;
	unsigned char* ms_fres;
} ms_ocall_readdn2label_t;

typedef struct ms_ocall_readdn3label_t {
	int ms_retval;
	unsigned char* ms_fres;
} ms_ocall_readdn3label_t;

typedef struct ms_ocall_writeoutputfile_t {
	int ms_m;
} ms_ocall_writeoutputfile_t;

typedef struct ms_ocall_writeoutputfile2_t {
	char* ms_m;
} ms_ocall_writeoutputfile2_t;

typedef struct ms_ocall_time1_t {
	int ms_retval;
} ms_ocall_time1_t;

typedef struct ms_ocall_time_t {
	int ms_retval;
} ms_ocall_time_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_strcpy(void* pms)
{
	ms_ocall_strcpy_t* ms = SGX_CAST(ms_ocall_strcpy_t*, pms);
	ocall_strcpy(ms->ms_DeStr, ms->ms_SoStr, ms->ms_DeLen, ms->ms_SoLen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sprintf(void* pms)
{
	ms_ocall_sprintf_t* ms = SGX_CAST(ms_ocall_sprintf_t*, pms);
	ocall_sprintf(ms->ms_pt, ms->ms_ipt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_input(void* pms)
{
	ms_ocall_input_t* ms = SGX_CAST(ms_ocall_input_t*, pms);
	ocall_input(ms->ms_input);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendn1sgx(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opendn1sgx();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdn1sgx(void* pms)
{
	ms_ocall_readdn1sgx_t* ms = SGX_CAST(ms_ocall_readdn1sgx_t*, pms);
	ms->ms_retval = ocall_readdn1sgx(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedn1sgx(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closedn1sgx();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendn2sgx(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opendn2sgx();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdn2sgx(void* pms)
{
	ms_ocall_readdn2sgx_t* ms = SGX_CAST(ms_ocall_readdn2sgx_t*, pms);
	ms->ms_retval = ocall_readdn2sgx(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedn2sgx(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closedn2sgx();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendn3sgx(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opendn3sgx();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdn3sgx(void* pms)
{
	ms_ocall_readdn3sgx_t* ms = SGX_CAST(ms_ocall_readdn3sgx_t*, pms);
	ms->ms_retval = ocall_readdn3sgx(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedn3sgx(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closedn3sgx();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opensgxdn1(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opensgxdn1();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writesgxdn1(void* pms)
{
	ms_ocall_writesgxdn1_t* ms = SGX_CAST(ms_ocall_writesgxdn1_t*, pms);
	ocall_writesgxdn1(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closesgxdn1(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closesgxdn1();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opensgxdn2(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opensgxdn2();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writesgxdn2(void* pms)
{
	ms_ocall_writesgxdn2_t* ms = SGX_CAST(ms_ocall_writesgxdn2_t*, pms);
	ocall_writesgxdn2(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closesgxdn2(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closesgxdn2();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opensgxdn3(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opensgxdn3();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writesgxdn3(void* pms)
{
	ms_ocall_writesgxdn3_t* ms = SGX_CAST(ms_ocall_writesgxdn3_t*, pms);
	ocall_writesgxdn3(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closesgxdn3(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closesgxdn3();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_openoutfile1(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_openoutfile1();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writeoutfile1(void* pms)
{
	ms_ocall_writeoutfile1_t* ms = SGX_CAST(ms_ocall_writeoutfile1_t*, pms);
	ocall_writeoutfile1(ms->ms_m1);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closeoutfile1(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closeoutfile1();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_openoutfile2(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_openoutfile2();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writeoutfile2(void* pms)
{
	ms_ocall_writeoutfile2_t* ms = SGX_CAST(ms_ocall_writeoutfile2_t*, pms);
	ocall_writeoutfile2(ms->ms_m2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closeoutfile2(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closeoutfile2();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_openoutfile3(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_openoutfile3();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writeoutfile3(void* pms)
{
	ms_ocall_writeoutfile3_t* ms = SGX_CAST(ms_ocall_writeoutfile3_t*, pms);
	ocall_writeoutfile3(ms->ms_m3);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closeoutfile3(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closeoutfile3();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendn1label(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opendn1label();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdn1label(void* pms)
{
	ms_ocall_readdn1label_t* ms = SGX_CAST(ms_ocall_readdn1label_t*, pms);
	ms->ms_retval = ocall_readdn1label(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedn1label(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closedn1label();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendn2label(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opendn2label();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdn2label(void* pms)
{
	ms_ocall_readdn2label_t* ms = SGX_CAST(ms_ocall_readdn2label_t*, pms);
	ms->ms_retval = ocall_readdn2label(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedn2label(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closedn2label();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendn3label(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_opendn3label();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdn3label(void* pms)
{
	ms_ocall_readdn3label_t* ms = SGX_CAST(ms_ocall_readdn3label_t*, pms);
	ms->ms_retval = ocall_readdn3label(ms->ms_fres);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedn3label(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closedn3label();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_openoutputfile(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_openoutputfile();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writeoutputfile(void* pms)
{
	ms_ocall_writeoutputfile_t* ms = SGX_CAST(ms_ocall_writeoutputfile_t*, pms);
	ocall_writeoutputfile(ms->ms_m);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writeoutputfile2(void* pms)
{
	ms_ocall_writeoutputfile2_t* ms = SGX_CAST(ms_ocall_writeoutputfile2_t*, pms);
	ocall_writeoutputfile2(ms->ms_m);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closeoutputfile(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_closeoutputfile();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_startclock1(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_startclock1();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_endclock1(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_endclock1();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_time1(void* pms)
{
	ms_ocall_time1_t* ms = SGX_CAST(ms_ocall_time1_t*, pms);
	ms->ms_retval = ocall_time1();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_startclock(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_startclock();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_endclock(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_endclock();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[50];
} ocall_table_Enclave = {
	50,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_strcpy,
		(void*)Enclave_ocall_sprintf,
		(void*)Enclave_ocall_input,
		(void*)Enclave_ocall_opendn1sgx,
		(void*)Enclave_ocall_readdn1sgx,
		(void*)Enclave_ocall_closedn1sgx,
		(void*)Enclave_ocall_opendn2sgx,
		(void*)Enclave_ocall_readdn2sgx,
		(void*)Enclave_ocall_closedn2sgx,
		(void*)Enclave_ocall_opendn3sgx,
		(void*)Enclave_ocall_readdn3sgx,
		(void*)Enclave_ocall_closedn3sgx,
		(void*)Enclave_ocall_opensgxdn1,
		(void*)Enclave_ocall_writesgxdn1,
		(void*)Enclave_ocall_closesgxdn1,
		(void*)Enclave_ocall_opensgxdn2,
		(void*)Enclave_ocall_writesgxdn2,
		(void*)Enclave_ocall_closesgxdn2,
		(void*)Enclave_ocall_opensgxdn3,
		(void*)Enclave_ocall_writesgxdn3,
		(void*)Enclave_ocall_closesgxdn3,
		(void*)Enclave_ocall_openoutfile1,
		(void*)Enclave_ocall_writeoutfile1,
		(void*)Enclave_ocall_closeoutfile1,
		(void*)Enclave_ocall_openoutfile2,
		(void*)Enclave_ocall_writeoutfile2,
		(void*)Enclave_ocall_closeoutfile2,
		(void*)Enclave_ocall_openoutfile3,
		(void*)Enclave_ocall_writeoutfile3,
		(void*)Enclave_ocall_closeoutfile3,
		(void*)Enclave_ocall_opendn1label,
		(void*)Enclave_ocall_readdn1label,
		(void*)Enclave_ocall_closedn1label,
		(void*)Enclave_ocall_opendn2label,
		(void*)Enclave_ocall_readdn2label,
		(void*)Enclave_ocall_closedn2label,
		(void*)Enclave_ocall_opendn3label,
		(void*)Enclave_ocall_readdn3label,
		(void*)Enclave_ocall_closedn3label,
		(void*)Enclave_ocall_openoutputfile,
		(void*)Enclave_ocall_writeoutputfile,
		(void*)Enclave_ocall_writeoutputfile2,
		(void*)Enclave_ocall_closeoutputfile,
		(void*)Enclave_ocall_startclock1,
		(void*)Enclave_ocall_endclock1,
		(void*)Enclave_ocall_time1,
		(void*)Enclave_ocall_startclock,
		(void*)Enclave_ocall_endclock,
		(void*)Enclave_ocall_time,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid, int mm, char* ssk)
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	ms.ms_mm = mm;
	ms.ms_ssk = ssk;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_update(sgx_enclave_id_t eid, int dnc)
{
	sgx_status_t status;
	ms_ecall_update_t ms;
	ms.ms_dnc = dnc;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_orderby(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_output(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

