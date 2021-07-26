/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <iostream>
//#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
//#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
#include <fstream>
using namespace std;

int NB = 10;//sgx内存大小
int mm = 0;//Label数
char ssk[17] = ""; //密钥
int ssklen = 0;//密钥长度字符数

FILE *dn1sgx;
FILE *dn2sgx;
FILE *dn3sgx;
FILE *sgxdn1;
FILE *sgxdn2;
FILE *sgxdn3;
FILE *sgxM1;
FILE *sgxM2;
FILE *sgxM3;
FILE *dn1label;
FILE *dn2label;
FILE *dn3label;

map<int, string> DN1;//获取的密文
map<int, string> DN2;
map<int, string> DN3;
map<int, int> M1;//每个DN属于不同Label的数量
map<int, int> M2;
map<int, int> M3;
map<int, vector<int>> Key_M1;
map<int, vector<int>> Key_M2;
map<int, vector<int>> Key_M3;
map<int, string> Sort_DN1;//部分排序后密文
map<int, string> Sort_DN2;
map<int, string> Sort_DN3;
map<int, string> Label_DN1;//按照Label获取的密文
map<int, string> Label_DN2;
map<int, string> Label_DN3;

map<int, vector<int>> Lpt;
map<int, int> Orderpt;
map<int, string> Orderct;//最终排序好密文

int o = 1;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


void ocall_strcpy(char *DeStr,char *SoStr,size_t DeLen,size_t SoLen)
{
    if (DeLen > SoLen)
        DeLen = SoLen;
    if (DeLen)
        memcpy(DeStr,SoStr,DeLen);
}

void ocall_sprintf(char *pt, int ipt)
{
	sprintf(pt, "%d", ipt);
}
void getmsk()
{
	ifstream de("../text/c_to_sgx.txt");
	de >> ssk >> mm;
	de.close();
	//printf("%s\n", ssk);
	cout << "密钥ssk：" << ssk << " Label数量mm:" << mm << endl;
	//ssklen=strlen(ssk);
}


void ocall_getSortDNi(int dnc,map<int, string> Sort_DN,int len)
{
	if (dnc == 1)
	{
		for(int i=1;i<=len;i++)
		{
			Sort_DN1[i]=Sort_DN[i];
		}
	}
	if (dnc == 2)
	{
		for(int i=1;i<=len;i++)
		{
			Sort_DN2[i]=Sort_DN[i];
		}
	}
	if (dnc == 3)
	{
		for(int i=1;i<=len;i++)
		{
			Sort_DN3[i]=Sort_DN[i];
		}
	}
}
void ocall_getMi(int dnc,map<int, int> M,int len)
{
	if (dnc == 1)
	{
		for(int i=1;i<=len;i++)
		{
			M1[i]=M[i];
		}
	}
	if (dnc == 2)
	{
		for(int i=1;i<=len;i++)
		{
			M2[i]=M[i];
		}
	}
	if (dnc == 3)
	{
		for(int i=1;i<=len;i++)
		{
			M3[i]=M[i];
		}
	}
}



//获取DN发过来的NB个密文
void getDN(int dnc)
{
	if (dnc == 1)
	{
		int cn1 = 0;
		dn1sgx = fopen("../text/DN1_to_sgx.dat", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int j = 0;
		int a1 = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn1sgx, "%02x", &res[j]) == EOF) {
					a1 = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a1 == 1)
				break;

			cn1++;

			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			printf("DN1密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");

			DN1[cn1].assign((char*)fres,17);


		}

		cout << "DN1密文已全部接收完毕！" << endl;
		fclose(dn1sgx);

	}

	else if (dnc == 2)
	{
		int cn2 = 0;
		dn2sgx = fopen("../text/DN2_to_sgx.dat", "rb");

		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int j = 0;
		int a2=0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn2sgx, "%02x", &res[j]) == EOF) {
					a2 = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a2 == 1)
				break;

			cn2++;
			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			printf("fres密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");

			DN2[cn2].assign((char*)fres,17);
		}

		cout << "DN2密文已全部接收完毕！" << endl;
		fclose(dn2sgx);

	}

	else if (dnc == 3)
	{
		int cn3 = 0;
		dn3sgx = fopen("../text/DN3_to_sgx.dat", "rb");

		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int j = 0;
		int a3 = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn3sgx, "%02x", &res[j]) == EOF) {
					a3 = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a3 == 1)
				break;

			cn3++;

			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			printf("fres密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");

			DN3[cn3].assign((char*)fres,17);

		}

		cout << "DN3密文已全部接收完毕！" << endl;
		fclose(dn3sgx);

	}

}

//读取密文并进行部分排序并发送给DN
void B_update(int dnc)
{
	int input = 0;
	unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
	while (1)
	{
		cout << "接收DN" << dnc << "，发送Mi、Sort_DNi给DN" << dnc << "请输入1：" << endl;
		cin >> input;

		getDN(dnc);//获得DNi

		//ecall_getSortDN(dnc);//获得Mi、Sort_DNi

		if (dnc == 1)
		{
			//ecall_getSortDN(1,DN1);//获得M1、Sort_DN1

			//清空输出的文件sgx_to_DN1.dat
			sgxdn1 = fopen("../text/sgx_to_DN1.dat", "wb");//输出Sort_DN1

			for (int t = 1; t <= Sort_DN1.size() ; t++)
			{
				fres=(unsigned char*)Sort_DN1[t].c_str();
				//传一个密文到文件中
				//printf("fres = ");
				for (int i = 0; i < 17; i++)
				{
					//printf("%02x,", fres[i]);
					fprintf(sgxdn1, "%02x", fres[i]);
					fprintf(sgxdn1, "\r\n");
				}
				//printf("\n");

			}
			fclose(sgxdn1);

			ofstream outfile1;//输出M1
			outfile1.open("../text/sgx_to_DN1M1.txt");
			for(int p=1;p<=M1.size();p++){
				//cout << M1[p] << " ";
				outfile1 << M1[p] << " ";
			}
			//cout<<endl;
			outfile1.close();

			cout << endl << "********sgx已发送给DN1 M1、Sort_DN1！" << endl;
			

			if (DN1.size() != NB)
			{
				cout << "Sort_DN1密文已全部发送完毕！" << endl;
				break;
			}
		}
		else if (dnc == 2)
		{
			//ecall_getSortDN(2,DN2);//获得M2、Sort_DN2
			//清空输出的文件sgx_to_DN2.dat
			sgxdn2 = fopen("../text/sgx_to_DN2.dat", "wb");

			for (int t = 1; t <= Sort_DN2.size()  ; t++)
			{
				fres=(unsigned char*)Sort_DN2[t].c_str();
				//传一个密文到文件中
				//printf("Sort_DN2[] = ");
				for (int i = 0; i < 17; i++)
				{
					//printf("%02x,", fres[i]);
					fprintf(sgxdn2, "%02x", fres[i]);
					fprintf(sgxdn2, "\r\n");
				}
				//printf("\n");

			}
			fclose(sgxdn2);
			ofstream outfile2;//输出M2
			outfile2.open("../text/sgx_to_DN2M2.txt");
			for(int p=1;p<=M2.size();p++){
				//cout << M2[p] << " ";
				outfile2 << M2[p] << " ";
			}
			//cout<<endl;
			outfile2.close();

			cout << endl << "********sgx已发送给DN2 M2、Sort_DN2！" << endl;
			

			if (DN2.size() != NB)
			{
				cout << "Sort_DN2密文已全部发送完毕！" << endl;
				break;
			}
		}

		else if (dnc == 3)
		{
			//ecall_getSortDN(3,DN3);//获得M3、Sort_DN3
			//清空输出的文件sgx_to_DN1.dat
			sgxdn3 = fopen("../text/sgx_to_DN3.dat", "wb");

			for (int t = 1; t <= Sort_DN3.size() ; t++)
			{
				fres=(unsigned char*)Sort_DN3[t].c_str();
				//传一个密文到文件中
				//printf("Sort_DN3[] = ");
				for (int i = 0; i < 17; i++)
				{
					//printf("%02x,", fres[i]);
					fprintf(sgxdn3, "%02x", fres[i]);
					fprintf(sgxdn3, "\r\n");
				}
				//printf("\n");

			}
			fclose(sgxdn3);

			ofstream outfile3;//输出M3
			outfile3.open("../text/sgx_to_DN3M3.txt");
			for(int p=1;p<=M3.size();p++){
				//cout << M3[p] << " ";
				outfile3 << M3[p] << " ";
			}
			//cout<<endl;
			outfile3.close();

			cout << endl << "********sgx已发送给DN3 M3、Sort_DN3！" << endl;


			if (DN3.size() != NB)
			{
				cout << "Sort_DN3密文已全部发送完毕！" << endl;
				break;
			}
		}

		DN1.clear();
		DN2.clear();
		DN3.clear();
		Sort_DN1.clear();
		Sort_DN2.clear();
		Sort_DN3.clear();
		M1.clear();
		M2.clear();
		M3.clear();
		//Key_M1.clear();
		//Key_M2.clear();
		//Key_M3.clear();

	}
}


//获取DN发过来的每个Label的密文
void getlabel(int dnc)
{
	if (dnc == 1)
	{
		int cn1 = 0;
		dn1label = fopen("DN1_to_sgxLabel.dat", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int j = 0;
		int a1 = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn1label, "%02x", &res[j]) == EOF) {
					a1 = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a1 == 1)
				break;

			cn1++;

			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			printf("Label_DN1[]密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");

			Label_DN1[cn1].assign((char*)fres,17);


		}

	}
	else if (dnc == 2)
	{
		int cn2 = 0;
		dn2label = fopen("DN2_to_sgxLabel.dat", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
		
		int j = 0;
		int a2 = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn2label, "%02x", &res[j]) == EOF) {
					a2 = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a2 == 1)
				break;

			cn2++;

			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			printf("Label_DN2[]密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");

			Label_DN2[cn2].assign((char*)fres,17);


		}

	}	
	else if (dnc == 3)
	{
		int cn3 = 0;
		dn3label = fopen("DN3_to_sgxLabel.dat", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int j = 0;
		int a3 = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn3label, "%02x", &res[j]) == EOF) {
					a3 = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a3 == 1)
				break;

			cn3++;

			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			printf("Label_DN3[]密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");

			Label_DN3[cn3].assign((char*)fres,17);


		}

	}
}

void B_orderby()
{

	int label=0;
	for (int i = 1; i <= mm; i++)
	{
		cout<<endl<<"排序三个DN的Label "<<i<<" 请输入"<<i<<endl;
		cin>>label;

		getlabel(1);
		getlabel(2);
		getlabel(3);

		//ecall_orderby(Label_DN1,Label_DN2,Label_DN3);//对所有密文进行排序
		Label_DN1.clear();
		Label_DN2.clear();
		Label_DN3.clear();
	}
	fclose(dn1label);
	fclose(dn2label);
	fclose(dn3label);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
	//enclave获取m，sk
    getmsk();
    ecall_init(global_eid,mm,ssk);

	//对三个DN分别进行部分排序
	/*B_update(1);
	B_update(2);
	B_update(3);

	//最终排序
	B_orderby();
	//输出排序结果
	ecall_output(global_eid);
	
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    

    return 0;
}

