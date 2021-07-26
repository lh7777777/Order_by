#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_t* ms = SGX_CAST(ms_ecall_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_ssk = ms->ms_ssk;
	size_t _len_ssk = 17;
	char* _in_ssk = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ssk, _len_ssk);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ssk != NULL && _len_ssk != 0) {
		if ( _len_ssk % sizeof(*_tmp_ssk) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ssk = (char*)malloc(_len_ssk);
		if (_in_ssk == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ssk, _len_ssk, _tmp_ssk, _len_ssk)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_init(ms->ms_mm, _in_ssk);

err:
	if (_in_ssk) free(_in_ssk);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_t* ms = SGX_CAST(ms_ecall_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_update(ms->ms_dnc);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_orderby(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_orderby();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_output(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_output();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_update, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_orderby, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_output, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[40][4];
} g_dyn_entry_table = {
	40,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_strcpy(char* DeStr, char* SoStr, size_t DeLen, size_t SoLen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_DeStr = DeLen;
	size_t _len_SoStr = SoLen;

	ms_ocall_strcpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_strcpy_t);
	void *__tmp = NULL;

	void *__tmp_DeStr = NULL;

	CHECK_ENCLAVE_POINTER(DeStr, _len_DeStr);
	CHECK_ENCLAVE_POINTER(SoStr, _len_SoStr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (DeStr != NULL) ? _len_DeStr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (SoStr != NULL) ? _len_SoStr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_strcpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_strcpy_t));
	ocalloc_size -= sizeof(ms_ocall_strcpy_t);

	if (DeStr != NULL) {
		ms->ms_DeStr = (char*)__tmp;
		__tmp_DeStr = __tmp;
		if (_len_DeStr % sizeof(*DeStr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_DeStr, 0, _len_DeStr);
		__tmp = (void *)((size_t)__tmp + _len_DeStr);
		ocalloc_size -= _len_DeStr;
	} else {
		ms->ms_DeStr = NULL;
	}
	
	if (SoStr != NULL) {
		ms->ms_SoStr = (char*)__tmp;
		if (_len_SoStr % sizeof(*SoStr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, SoStr, _len_SoStr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_SoStr);
		ocalloc_size -= _len_SoStr;
	} else {
		ms->ms_SoStr = NULL;
	}
	
	ms->ms_DeLen = DeLen;
	ms->ms_SoLen = SoLen;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (DeStr) {
			if (memcpy_s((void*)DeStr, _len_DeStr, __tmp_DeStr, _len_DeStr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sprintf(char* pt, int ipt)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pt = 17;

	ms_ocall_sprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sprintf_t);
	void *__tmp = NULL;

	void *__tmp_pt = NULL;

	CHECK_ENCLAVE_POINTER(pt, _len_pt);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pt != NULL) ? _len_pt : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sprintf_t));
	ocalloc_size -= sizeof(ms_ocall_sprintf_t);

	if (pt != NULL) {
		ms->ms_pt = (char*)__tmp;
		__tmp_pt = __tmp;
		if (_len_pt % sizeof(*pt) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_pt, 0, _len_pt);
		__tmp = (void *)((size_t)__tmp + _len_pt);
		ocalloc_size -= _len_pt;
	} else {
		ms->ms_pt = NULL;
	}
	
	ms->ms_ipt = ipt;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (pt) {
			if (memcpy_s((void*)pt, _len_pt, __tmp_pt, _len_pt)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_input(int input)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_input_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_input_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_input_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_input_t));
	ocalloc_size -= sizeof(ms_ocall_input_t);

	ms->ms_input = input;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_opendn1sgx(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(4, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_readdn1sgx(int* retval, unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_readdn1sgx_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdn1sgx_t);
	void *__tmp = NULL;

	void *__tmp_fres = NULL;

	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdn1sgx_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdn1sgx_t));
	ocalloc_size -= sizeof(ms_ocall_readdn1sgx_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		__tmp_fres = __tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fres, 0, _len_fres);
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fres) {
			if (memcpy_s((void*)fres, _len_fres, __tmp_fres, _len_fres)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedn1sgx(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(6, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opendn2sgx(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(7, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_readdn2sgx(int* retval, unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_readdn2sgx_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdn2sgx_t);
	void *__tmp = NULL;

	void *__tmp_fres = NULL;

	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdn2sgx_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdn2sgx_t));
	ocalloc_size -= sizeof(ms_ocall_readdn2sgx_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		__tmp_fres = __tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fres, 0, _len_fres);
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fres) {
			if (memcpy_s((void*)fres, _len_fres, __tmp_fres, _len_fres)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedn2sgx(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(9, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opendn3sgx(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(10, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_readdn3sgx(int* retval, unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_readdn3sgx_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdn3sgx_t);
	void *__tmp = NULL;

	void *__tmp_fres = NULL;

	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdn3sgx_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdn3sgx_t));
	ocalloc_size -= sizeof(ms_ocall_readdn3sgx_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		__tmp_fres = __tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fres, 0, _len_fres);
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fres) {
			if (memcpy_s((void*)fres, _len_fres, __tmp_fres, _len_fres)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedn3sgx(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(12, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opensgxdn1(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(13, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_writesgxdn1(unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_writesgxdn1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writesgxdn1_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writesgxdn1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writesgxdn1_t));
	ocalloc_size -= sizeof(ms_ocall_writesgxdn1_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, fres, _len_fres)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closesgxdn1(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(15, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opensgxdn2(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(16, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_writesgxdn2(unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_writesgxdn2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writesgxdn2_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writesgxdn2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writesgxdn2_t));
	ocalloc_size -= sizeof(ms_ocall_writesgxdn2_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, fres, _len_fres)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closesgxdn2(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(18, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opensgxdn3(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(19, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_writesgxdn3(unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_writesgxdn3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writesgxdn3_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writesgxdn3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writesgxdn3_t));
	ocalloc_size -= sizeof(ms_ocall_writesgxdn3_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, fres, _len_fres)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closesgxdn3(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(21, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_openoutfile1(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(22, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_writeoutfile1(int m1)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_writeoutfile1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writeoutfile1_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writeoutfile1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writeoutfile1_t));
	ocalloc_size -= sizeof(ms_ocall_writeoutfile1_t);

	ms->ms_m1 = m1;
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closeoutfile1(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(24, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_openoutfile2(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(25, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_writeoutfile2(int m2)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_writeoutfile2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writeoutfile2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writeoutfile2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writeoutfile2_t));
	ocalloc_size -= sizeof(ms_ocall_writeoutfile2_t);

	ms->ms_m2 = m2;
	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closeoutfile2(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(27, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_openoutfile3(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(28, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_writeoutfile3(int m3)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_writeoutfile3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writeoutfile3_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writeoutfile3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writeoutfile3_t));
	ocalloc_size -= sizeof(ms_ocall_writeoutfile3_t);

	ms->ms_m3 = m3;
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closeoutfile3(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(30, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opendn1label(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(31, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_readdn1label(int* retval, unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_readdn1label_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdn1label_t);
	void *__tmp = NULL;

	void *__tmp_fres = NULL;

	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdn1label_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdn1label_t));
	ocalloc_size -= sizeof(ms_ocall_readdn1label_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		__tmp_fres = __tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fres, 0, _len_fres);
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fres) {
			if (memcpy_s((void*)fres, _len_fres, __tmp_fres, _len_fres)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedn1label(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(33, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opendn2label(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(34, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_readdn2label(int* retval, unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_readdn2label_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdn2label_t);
	void *__tmp = NULL;

	void *__tmp_fres = NULL;

	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdn2label_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdn2label_t));
	ocalloc_size -= sizeof(ms_ocall_readdn2label_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		__tmp_fres = __tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fres, 0, _len_fres);
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fres) {
			if (memcpy_s((void*)fres, _len_fres, __tmp_fres, _len_fres)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedn2label(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(36, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_opendn3label(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(37, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_readdn3label(int* retval, unsigned char* fres)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fres = 17;

	ms_ocall_readdn3label_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdn3label_t);
	void *__tmp = NULL;

	void *__tmp_fres = NULL;

	CHECK_ENCLAVE_POINTER(fres, _len_fres);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fres != NULL) ? _len_fres : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdn3label_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdn3label_t));
	ocalloc_size -= sizeof(ms_ocall_readdn3label_t);

	if (fres != NULL) {
		ms->ms_fres = (unsigned char*)__tmp;
		__tmp_fres = __tmp;
		if (_len_fres % sizeof(*fres) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fres, 0, _len_fres);
		__tmp = (void *)((size_t)__tmp + _len_fres);
		ocalloc_size -= _len_fres;
	} else {
		ms->ms_fres = NULL;
	}
	
	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (fres) {
			if (memcpy_s((void*)fres, _len_fres, __tmp_fres, _len_fres)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedn3label(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(39, NULL);

	return status;
}
