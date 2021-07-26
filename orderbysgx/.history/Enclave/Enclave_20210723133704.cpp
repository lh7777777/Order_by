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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>

#include <iostream>
//#include <stdio.h>
//#include <openssl/aes.h>
//#include <openssl/md5.h>
//#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
#include <fstream>
using namespace std;

int NB = 10;//sgx内存大小
int m = 0;//Label数
char sk[17] = ""; //密钥
//char* sk;
int sklen = 0;//密钥长度字符数


std::map<int,std:: string> DN1;//获取的密文
std::map<int, std::string> DN2;
std::map<int, std::string> DN3;
std::map<int, int> M1;//每个DN属于不同Label的数量
std::map<int, int> M2;
std::map<int, int> M3;
std::map<int, vector<int>> Key_M1;
std::map<int, vector<int>> Key_M2;
std::map<int, vector<int>> Key_M3;
std::map<int, std::string> Sort_DN1;//部分排序后密文
std::map<int, std::string> Sort_DN2;
std::map<int, std::string> Sort_DN3;
//map<int, string> Label_DN1;//按照Label获取的密文
//map<int, string> Label_DN2;
//map<int, string> Label_DN3;

std::map<int, vector<int>> Lpt;
std::map<int, int> Orderpt;
std::map<int,std:: string> Orderct;//最终排序好密文

int o = 1;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    //return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


/*void ecall_init()
{
	ocall_getm(&m);
	ocall_getsk(&sk);
	printf("%s\n",sk);
	sklen=strlen(sk);
}*/

//获取sk和m
void ecall_init(int mm,char* ssk)
{

	m=mm;
	ocall_strcpy(sk,ssk,17,17);
	printf("%d\n", m);
	printf("%s\n", sk);
}

//对每个DN的NB个密文进行部分排序
void part_sort(map<int,string> DN, int dnc)
{

	if (dnc == 1)
	{
		int t = 1;
		for (int k = 1; k <= m; k++)
		{

			if (M1[k] != 0)
			{
				for (int h = 0; h < M1[k]; h++)
				{
					Sort_DN1[t].append(DN[Key_M1[k][h]], 0, 17);

					t++;
				}
			}
		}

		//cout << endl << "************部分排序完Sort_DN1为：" << endl;
		AES_KEY k;
		AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		for (int i = 1; i <= Sort_DN1.size(); i++)
		{
			//cout << " Sort_DN1[]：" << Sort_DN1[i] << endl;

			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			AES_decrypt((unsigned char*)Sort_DN1[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
		}

	}
	else if (dnc == 2)
	{
		int t = 1;
		for (int k = 1; k <= m; k++)
		{
			if (M2[k] != 0)
			{
				for (int h = 0; h < M2[k]; h++)
				{
					Sort_DN2[t].append(DN[Key_M2[k][h]], 0, 17);
					t++;
				}
			}
		}

		//cout << endl << "************部分排序完Sort_DN2为：" << endl;
		AES_KEY k;
		AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		for (int i = 1; i <= Sort_DN2.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			AES_decrypt((unsigned char*)Sort_DN2[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
		}

	}
	else if (dnc == 3)
	{
		int t = 1;
		for (int k = 1; k <= m; k++)
		{
			if (M3[k] != 0)
			{
				for (int h = 0; h < M3[k]; h++)
				{
					Sort_DN3[t].append(DN[Key_M3[k][h]], 0, 17);
					t++;
				}
			}
		}

		AES_KEY k;
		AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		//cout <<endl<< "************部分排序完Sort_DN3为：" << endl;
		for (int i = 1; i <= Sort_DN3.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			AES_decrypt((unsigned char*)Sort_DN3[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
		}

	}

}
//部分排序
void ecall_getSortDN(int dnc,map<int, string> DN)
{
	if (dnc == 1)
	{

		//解密
		AES_KEY k;
		AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		for (int i = 1; i <= DN.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文


			AES_decrypt((unsigned char*)DN[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
			//按照label存入M1
			for (int j = 1; j <= m; j++)
			{
				if (mint <= j * NB && mint >= ((j - 1)*NB + 1))
				{
					//cout << "label " << j << " : " << mint << endl;
					M1[j]++;
					Key_M1[j].push_back(i);//把属于此label的key添加到此map中，方便后续排序
				}
			}


		}
		part_sort(DN, dnc);
		//将M1和Sort_DN1给外面
		ocall_getSortDNi(1,Sort_DN1,Sort_DN1.size());
		ocall_getMi(1,M1,m);
	}

	else if (dnc == 2)
	{
		//解密
		AES_KEY k;
		AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		for (int i = 1; i <= DN.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			AES_decrypt((unsigned char*)DN[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
			//按照label存入M2
			for (int j = 1; j <= m; j++)
			{
				if (mint <= j * NB && mint >= ((j - 1)*NB + 1))
				{
					//cout << "label " << j << " : " << mint << endl;
					M2[j]++;
					Key_M2[j].push_back(i);//把属于此label的key添加到此map中，方便后续排序
				}
			}
		}
		part_sort(DN, dnc);
		//将M2和Sort_DN2给外面
		ocall_getSortDNi(2,Sort_DN2,Sort_DN2.size());
		ocall_getMi(2,M2,m);

	}

	else if (dnc == 3)
	{
		//解密
		AES_KEY k;
		AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		for (int i = 1; i <= DN.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			AES_decrypt((unsigned char*)DN[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
			//按照label存入M3
			for (int j = 1; j <= m; j++)
			{
				if (mint <= j * NB && mint >= ((j - 1)*NB + 1))
				{
					//cout << "label " << j << " : " << mint << endl;
					M3[j]++;
					Key_M3[j].push_back(i);//把属于此label的key添加到此map中，方便后续排序
				}
			}
		}
		part_sort(DN, dnc);
		//将M3和Sort_DN3给外面
		ocall_getSortDNi(3,Sort_DN3,Sort_DN3.size());
		ocall_getMi(3,M3,m);

	}
	Sort_DN1.clear();
	Sort_DN2.clear();
	Sort_DN3.clear();
	M1.clear();
	M2.clear();
	M3.clear();
	Key_M1.clear();
	Key_M2.clear();
	Key_M3.clear();

}
//快速排序
void quickSort(int left, int right, std::vector<int>& arr)
{
	if (left >= right)
		return;
	int i, j, base, temp;
	i = left, j = right;
	base = arr[left];  //取最左边的数为基准数
	while (i < j)
	{
		while (arr[j] >= base && i < j)
			j--;
		while (arr[i] <= base && i < j)
			i++;
		if (i < j)
		{
			temp = arr[i];
			arr[i] = arr[j];
			arr[j] = temp;
		}
	}
	//基准数归位
	arr[left] = arr[i];
	arr[i] = base;
	quickSort(left, i - 1, arr);//递归左边
	quickSort(i + 1, right, arr);//递归右边
}

//使用Label_DNi实现最终排序
void ecall_orderby(map<int, string> Label_DN1,map<int, string> Label_DN2,map<int, string> Label_DN3)
{
		
		//cout<<"Label_DN1:"<<endl;
		for (int j = 1; j <= Label_DN1.size(); j++)
		{
			AES_KEY k;
			AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文
			//AES解密
			AES_decrypt((unsigned char*)Label_DN1[j].c_str(), (unsigned char*)pt2, &k);
			//cout << " 明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << " , ";
			Lpt[o].push_back(mint);
		}
		cout<<endl;
		//cout<<"Label_DN2:"<<endl;
		for (int j = 1; j <= Label_DN2.size(); j++)
		{
			AES_KEY k;
			AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文
			//AES解密
			AES_decrypt((unsigned char*)Label_DN2[j].c_str(), (unsigned char*)pt2, &k);
			//cout << " 明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << " , ";
			Lpt[o].push_back(mint);
		}
		printf("\n");
		//cout<<"Label_DN3:"<<endl;
		for (int j = 1; j <= Label_DN3.size(); j++)
		{
			AES_KEY k;
			AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			AES_decrypt((unsigned char*)Label_DN3[j].c_str(), (unsigned char*)pt2, &k);
			//cout << " 明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << " , ";
			Lpt[o].push_back(mint);
		}
		cout<<endl;

		quickSort(0, Lpt[o].size() - 1, Lpt[o]);//明文排序后Lpt
		o++;
		//Label_DN1.clear();
		//Label_DN2.clear();
		//Label_DN3.clear();
}
void ecall_output()
{
	int t = 0;
	for (int i = 1; i <= m; i++)
	{
		for (int j = 0; j < Lpt[i].size(); j++)
		{
			t++;
			Orderpt[t] = Lpt[i][j];
			char pt[17] = { 0 };//每一个明文数字
			sprintf(pt, "%d", Orderpt[t]);//明文int转化为char
			char ct[17] = { 0 }; // 每一个AES密文
			AES_KEY k;
			//AES加密
			AES_set_encrypt_key((unsigned char*)sk, sklen * 8, &k);
			AES_encrypt((unsigned char*)pt, (unsigned char*)ct, &k);
			Orderct[t] = ct;
		}
	}

	//cout << "排序后明文：" << endl;
	printf("%s\n", "排序后明文：");
	for (int i = 1; i <= Orderpt.size(); i++)
	{
		//cout << Orderpt[i] << " ";
		printf("%d,", Orderpt[i]);
	}
	printf("\n");
	//cout << "排序后密文：" << endl;
	printf("%s\n", "排序后密文：");
	for (int i = 1; i <= Orderpt.size(); i++)
	{
		//cout << Orderct[i] << " ";
		printf("%s,", Orderct[i]);
	}
	printf("\n");
}
