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

//#include <iostream>
//#include <stdio.h>
//#include <openssl/aes.h>
//#include <openssl/md5.h>
//#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
//#include <fstream>
#include "aes.h"

//using namespace std;

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
std::map<int,std:: vector<int>> Key_M1;
std::map<int, std::vector<int>> Key_M2;
std::map<int, std::vector<int>> Key_M3;
std::map<int, std::string> Sort_DN1;//部分排序后密文
std::map<int, std::string> Sort_DN2;
std::map<int, std::string> Sort_DN3;
map<int, string> Label_DN1;//按照Label获取的密文
map<int, string> Label_DN2;
map<int, string> Label_DN3;

std::map<int, std::vector<int>> Lpt;
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
	sklen=strlen(sk);
}

//对每个DN的NB个密文进行部分排序
void part_sort(std::map<int,std::string> DN, int dnc)
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
		Aes Decryption;
        Decryption.getKey(sk);
        Decryption.initAes();

		//AES_KEY k;
		//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		for (int i = 1; i <= Sort_DN1.size(); i++)
		{
			//cout << " Sort_DN1[]：" << Sort_DN1[i] << endl;

			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			//AES_decrypt((unsigned char*)Sort_DN1[i].c_str(), (unsigned char*)pt2, &k);
			Decryption.decode((unsigned char*)Sort_DN1[i].c_str(),(unsigned char*)pt2);
			printf("解密后明文：%s\n", pt2);

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
		//AES_KEY k;
		//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		Aes Decryption;
        Decryption.getKey(sk);
        Decryption.initAes();

		for (int i = 1; i <= Sort_DN2.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			//AES_decrypt((unsigned char*)Sort_DN2[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			Decryption.decode((unsigned char*)Sort_DN2[i].c_str(),(unsigned char*)pt2);
			printf("解密后明文：%s\n", pt2);

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

		//AES_KEY k;
		//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		Aes Decryption;
        Decryption.getKey(sk);
        Decryption.initAes();

		//cout <<endl<< "************部分排序完Sort_DN3为：" << endl;
		for (int i = 1; i <= Sort_DN3.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			//AES_decrypt((unsigned char*)Sort_DN3[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			Decryption.decode((unsigned char*)Sort_DN3[i].c_str(),(unsigned char*)pt2);
			printf("解密后明文：%s\n", pt2);

			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << endl;
		}

	}

}
//获取DN发过来的NB个密文
void getDN(int dnc)
{
	if (dnc == 1)
	{
		int cn1 = 0;
		//dn1sgx = fopen("../text/DN1_to_sgx.dat", "rb");
		ocall_opendn1sgx();
		//unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int a1 = 0;
		while (1)
		{
			ocall_readdn1sgx(&a1,fres);

			if (a1 == 1)
				break;

			cn1++;
			DN1[cn1].assign((char*)fres,17);

			printf("DN1密文 = %s\n",DN1[cn1]);

		}
		//cout << "DN1密文已全部接收完毕！" << endl;
		ocall_closedn1sgx();

	}

	else if (dnc == 2)
	{
		int cn2 = 0;
		//dn1sgx = fopen("../text/DN1_to_sgx.dat", "rb");
		ocall_opendn2sgx();
		//unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int a2 = 0;
		while (1)
		{
			ocall_readdn2sgx(&a2,fres);

			if (a2 == 1)
				break;

			cn2++;
			DN2[cn2].assign((char*)fres,17);

			printf("DN2密文 = %s\n",DN2[cn2]);

		}
		//cout << "DN2密文已全部接收完毕！" << endl;
		ocall_closedn2sgx();

	}

	else if (dnc == 3)
	{
		int cn3 = 0;
		//dn1sgx = fopen("../text/DN1_to_sgx.dat", "rb");
		ocall_opendn3sgx();
		//unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int a3 = 0;
		while (1)
		{
			ocall_readdn3sgx(&a3,fres);

			if (a3 == 1)
				break;

			cn3++;
			DN3[cn3].assign((char*)fres,17);

			printf("DN3密文 = %s\n",DN3[cn3]);

		}
		//cout << "DN3密文已全部接收完毕！" << endl;
		ocall_closedn3sgx();
	}

}
//部分排序
void getSortDN(int dnc)
{
	if (dnc == 1)
	{

		//解密
		//AES_KEY k;
		//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		Aes Decryption;
        Decryption.getKey(sk);
        Decryption.initAes();

		for (int i = 1; i <= DN1.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文


			//AES_decrypt((unsigned char*)DN1[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			Decryption.decode((unsigned char*)DN1[i].c_str(),(unsigned char*)pt2);
			printf("解密后明文：%s\n", pt2);

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
		part_sort(DN1, dnc);
	}

	else if (dnc == 2)
	{
		//解密
		//AES_KEY k;
		//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		Aes Decryption;
        Decryption.getKey(sk);
        Decryption.initAes();

		for (int i = 1; i <= DN2.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES_decrypt((unsigned char*)DN2[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			Decryption.decode((unsigned char*)DN2[i].c_str(),(unsigned char*)pt2);
			printf("解密后明文：%s\n", pt2);

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
		part_sort(DN2, dnc);

	}

	else if (dnc == 3)
	{
		//解密
		//AES_KEY k;
		//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
		Aes Decryption;
        Decryption.getKey(sk);
        Decryption.initAes();

		for (int i = 1; i <= DN3.size(); i++)
		{
			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES_decrypt((unsigned char*)DN3[i].c_str(), (unsigned char*)pt2, &k);
			//cout << " 解密后明文：" << pt2;
			Decryption.decode((unsigned char*)DN3[i].c_str(),(unsigned char*)pt2);
			printf("解密后明文：%s\n", pt2);

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
		part_sort(DN3, dnc);
		//把Mi和部分排序好的密文Sort_DNi发给DNi

	}

}
void ecall_update(int dnc)
{
	int input = 0;
	unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
	while (1)
	{
		//cout << "接收DN" << dnc << "，发送Mi、Sort_DNi给DN" << dnc << "请输入1：" << endl;
		printf("接收DN %d，发送Mi、Sort_DNi给DN %d，请输入1：\n",dnc,dnc);
		ocall_input(input);
		//cin >> input;

		getDN(dnc);//获得DNi
		getSortDN(dnc);//获得Mi、Sort_DNi

		if (dnc == 1)
		{
			//清空输出的文件sgx_to_DN1.dat
			//sgxdn1 = fopen("../text/sgx_to_DN1.dat", "wb");//输出Sort_DN1
			ocall_opensgxdn1();

			for (int t = 1; t <= Sort_DN1.size() ; t++)
			{
				fres=(unsigned char*)Sort_DN1[t].c_str();
				//传一个密文到文件中
				ocall_writesgxdn1(fres);

			}
			//fclose(sgxdn1);
			ocall_closesgxdn1();

			//ofstream outfile1;//输出M1
			//outfile1.open("../text/sgx_to_DN1M1.txt");
			ocall_openoutfile1();
			for(int p=1;p<=M1.size();p++){
				//outfile1 << M1[p] << " ";
				ocall_writeoutfile1(M1[p]);
			}
			//outfile1.close();
			ocall_closeoutfile1();

			//cout << endl << "********sgx已发送给DN1 M1、Sort_DN1！" << endl;
			printf("\n********sgx已发送给DN1 M1、Sort_DN1！\n");

			if (DN1.size() != NB)
			{
				//cout << "Sort_DN1密文已全部发送完毕！" << endl;
				printf("Sort_DN1密文已全部发送完毕！\n");
				break;
			}
		}
		else if (dnc == 2)
		{
			//清空输出的文件sgx_to_DN2.dat
			//sgxdn2 = fopen("../text/sgx_to_DN2.dat", "wb");
			ocall_opensgxdn2();

			for (int t = 1; t <= Sort_DN2.size()  ; t++)
			{
				fres=(unsigned char*)Sort_DN2[t].c_str();
				//传一个密文到文件中
				ocall_writesgxdn2(fres);

			}
			//fclose(sgxdn2);
			ocall_closesgxdn2();

			//ofstream outfile2;//输出M2
			//outfile2.open("../text/sgx_to_DN2M2.txt");
			ocall_openoutfile2();
			for(int p=1;p<=M2.size();p++){
				//cout << M2[p] << " ";
				//outfile2 << M2[p] << " ";
				ocall_writeoutfile2(M2[p]);
			}
			//cout<<endl;
			//outfile2.close();
			ocall_closeoutfile2();

			//cout << endl << "********sgx已发送给DN2 M2、Sort_DN2！" << endl;
			printf("\n********sgx已发送给DN2 M2、Sort_DN2！\n");
			

			if (DN2.size() != NB)
			{
				//cout << "Sort_DN2密文已全部发送完毕！" << endl;
				printf("Sort_DN2密文已全部发送完毕！\n");
				break;
			}
		}

		else if (dnc == 3)
		{
			//清空输出的文件sgx_to_DN1.dat
			//sgxdn3 = fopen("../text/sgx_to_DN3.dat", "wb");
			ocall_opensgxdn3();

			for (int t = 1; t <= Sort_DN3.size() ; t++)
			{
				fres=(unsigned char*)Sort_DN3[t].c_str();
				//传一个密文到文件中
				ocall_writesgxdn3(fres);

			}
			//fclose(sgxdn3);
			ocall_closesgxdn3();

			//ofstream outfile3;//输出M3
			//outfile3.open("../text/sgx_to_DN3M3.txt");
			ocall_openoutfile3();
			for(int p=1;p<=M3.size();p++){
				//cout << M3[p] << " ";
				//outfile3 << M3[p] << " ";
				ocall_writeoutfile3(M3[p]);
			}
			//cout<<endl;
			//outfile3.close();
			ocall_closeoutfile3();

			//cout << endl << "********sgx已发送给DN3 M3、Sort_DN3！" << endl;
			printf("\n********sgx已发送给DN3 M3、Sort_DN3！\n");


			if (DN3.size() != NB)
			{
				//cout << "Sort_DN3密文已全部发送完毕！" << endl;
				printf("Sort_DN3密文已全部发送完毕！\n");
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
		Key_M1.clear();
		Key_M2.clear();
		Key_M3.clear();

	}
}


//获取DN发过来的每个Label的密文
void getlabel(int dnc)
{
	if (dnc == 1)
	{
		int cn1 = 0;
		//dn1label = fopen("DN1_to_sgxLabel.dat", "rb");
		ocall_opendn1label();
		//unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		//int j = 0;
		int a1 = 0;
		while (1)
		{
			ocall_readdn1label(&a1,fres);

			if (a1 == 1)
				break;

			cn1++;			

			Label_DN1[cn1].assign((char*)fres,17);

			printf("Label_DN1密文 = %s\n",Label_DN1[cn1]);
		}

	}
	else if (dnc == 2)
	{
		int cn2 = 0;
		//dn2label = fopen("DN2_to_sgxLabel.dat", "rb");
		ocall_opendn2label();
		//unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
		
		int a2 = 0;
		while (1)
		{
			ocall_readdn2label(&a2,fres);

			if (a2 == 1)
				break;

			cn2++;

			Label_DN2[cn2].assign((char*)fres,17);

			printf("Label_DN2密文 = %s\n",Label_DN2[cn2]);

		}

	}	
	else if (dnc == 3)
	{
		int cn3 = 0;
		//dn3label = fopen("DN3_to_sgxLabel.dat", "rb");
		ocall_opendn3label();
		//unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));

		int a3 = 0;
		while (1)
		{
			ocall_readdn3label(&a3,fres);

			if (a3 == 1)
				break;

			cn3++;
			
			Label_DN3[cn3].assign((char*)fres,17);

			printf("Label_DN3密文 = %s\n",Label_DN3[cn3]);

		}

	}
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
void ALL_orderby()
{
		getlabel(1);
		getlabel(2);
		getlabel(3);
		//cout<<"Label_DN1:"<<endl;
		for (int j = 1; j <= Label_DN1.size(); j++)
		{
			//AES_KEY k;
			//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
			Aes Decryption;
        	Decryption.getKey(sk);
        	Decryption.initAes();

			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文
			//AES解密
			//AES_decrypt((unsigned char*)Label_DN1[j].c_str(), (unsigned char*)pt2, &k);
			Decryption.decode((unsigned char*)Label_DN1[j].c_str(), (unsigned char*)pt2);

			//cout << " 明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << " , ";
			Lpt[o].push_back(mint);
		}
		//cout<<endl;
		printf("\n");

		//cout<<"Label_DN2:"<<endl;
		for (int j = 1; j <= Label_DN2.size(); j++)
		{
			//AES_KEY k;
			//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
			Aes Decryption;
        	Decryption.getKey(sk);
        	Decryption.initAes();

			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文
			//AES解密
			//AES_decrypt((unsigned char*)Label_DN2[j].c_str(), (unsigned char*)pt2, &k);
			Decryption.decode((unsigned char*)Label_DN2[j].c_str(), (unsigned char*)pt2);

			//cout << " 明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << " , ";
			Lpt[o].push_back(mint);
		}
		//cout<<endl;
		printf("\n");

		//cout<<"Label_DN3:"<<endl;
		for (int j = 1; j <= Label_DN3.size(); j++)
		{
			//AES_KEY k;
			//AES_set_decrypt_key((unsigned char*)sk, sklen * 8, &k);
			Aes Decryption;
        	Decryption.getKey(sk);
        	Decryption.initAes();

			char pt2[17] = { 0 }; // 每一个AES明文
			int mint = 0;//每一个int明文

			//AES解密
			//AES_decrypt((unsigned char*)Label_DN3[j].c_str(), (unsigned char*)pt2, &k);
			Decryption.decode((unsigned char*)Label_DN3[j].c_str(), (unsigned char*)pt2);

			//cout << " 明文：" << pt2;
			mint = atoi(pt2);
			//cout << " 转化为int后：" << mint << " , ";
			Lpt[o].push_back(mint);
		}
		//cout<<endl;
		printf("\n");

		quickSort(0, Lpt[o].size() - 1, Lpt[o]);//明文排序后Lpt
		o++;
		Label_DN1.clear();
		Label_DN2.clear();
		Label_DN3.clear();
}
void ecall_orderby()
{

	int label=0;
	for (int i = 1; i <= m; i++)
	{
		//cout<<endl<<"排序三个DN的Label "<<i<<" 请输入"<<i<<endl;
		//cin>>label;
		printf("\n排序三个DN的Label %d，请输入 %d：\n",i,i);
		ocall_input(label);
		
		ALL_orderby();//对所有密文进行排序
	}
	//fclose(dn1label);
	//fclose(dn2label);
	//fclose(dn3label);
	ocall_closedn1label();
	ocall_closedn2label();
	ocall_closedn3label();
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
			//sprintf(pt, "%d", Orderpt[t]);//明文int转化为char
			ocall_sprintf(pt, Orderpt[t]);
			char ct[17] = { 0 }; // 每一个AES密文
			AES_KEY k;
			//AES加密
			AES_set_encrypt_key((unsigned char*)sk, sklen * 8, &k);
			AES_encrypt((unsigned char*)pt, (unsigned char*)ct, &k);
			Orderct[t] = ct;
		}
	}

	//cout << "排序后明文：" << endl;
	printf("排序后明文：\n");
	for (int i = 1; i <= Orderpt.size(); i++)
	{
		//cout << Orderpt[i] << " ";
		printf("%d,", Orderpt[i]);
	}
	//cout << endl;
	//cout << "排序后密文：" << endl;
	printf("\n排序后密文：\n");
	for (int i = 1; i <= Orderpt.size(); i++)
	{
		//cout << Orderct[i] << " ";
		printf("%s,", Orderct[i]);
	}
	//cout << endl;
	printf("\n");
}
