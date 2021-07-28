#include <iostream>
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
#include <fstream>
using namespace std;

int NB = 2000;//sgx内存大小

map<int, string> Sort_DN1;//部分排序好密文
map<int, int> M1;//每个Label数量
int cnt1 = 0;
map<int, vector<string>> Label_DN1;//按照Label排序好密文
void Dn1_update();//获取密文并按NB个发送给sgx
void Dn1_orderby();//按Label排序好密文并发送给sgx

FILE *cdn;
FILE *dn1sgx;
FILE *sgxdn1;
FILE *sgxM1;
FILE *dn1label;

int a = 0;
int main()
{

	cdn=fopen("../text/c_to_DN1.dat","rb");

	int input = 0;
	int input2=0;
	while (1)
	{
		cout<<"发送DN1密文给sgx请输入1："<<endl;
		cin >> input;
		Dn1_update();//接收Client的密文并按照NB发给sgx
		fclose(dn1sgx);
		cout<<"接收Sort_DN1、M1请输入2："<<endl;
		cin >> input2;
		Dn1_orderby();//接收Sort_DN1、M1并存入Label_DN1

		if (a == 1)
		{
			cout << "DN1密文已全部发送完毕,Sort_DN1已全部接收完毕！" << endl << endl <<endl;

			break;
		}
		Sort_DN1.clear();
		M1.clear();

	}

	fclose(cdn);

	//发送Lable_DN1给sgx
	int label=0;
	unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
	for (int i = 1; i <= Label_DN1.size(); i++)
	{
		cout<<"发送DN1的Lable "<<i<<" 给sgx，请输入 "<<i<<endl;
		cin>>label;
			//清空输出的文件DN1_to_sgxLabel.dat
			dn1label = fopen("../text/DN1_to_sgxLabel.dat", "wb");//输出Label_DN1[i]

			for (int t = 0; t < Label_DN1[i].size() ; t++)
			{
				fres=(unsigned char*)Label_DN1[i][t].c_str();
				//传一个密文到文件中
				//printf("fres = ");
				for (int i = 0; i < 17; i++)
				{
					fprintf(dn1label, "%02x", fres[i]);
					fprintf(dn1label, "\r\n");
				}

			}
			fclose(dn1label);		
	}
	
	return 0;
}

void Dn1_update()
{

		//清空输出的文件DN1_to_sgx.dat
		dn1sgx = fopen("../text/DN1_to_sgx.dat", "wb");

		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
		int j = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(cdn, "%02x", &res[j]) == EOF) {
					a = 1;//判断是否读到文件末尾
					break;
				}
			}
			if (a == 1)
				break;
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}

			//传一个密文到文件中
			for (int i = 0; i < 17; i++)
			{
				fprintf(dn1sgx, "%02x", fres[i]);
				fprintf(dn1sgx, "\r\n");
			}

			cnt1++;
			
			if (cnt1 == NB)
			{
				//sgx读取文件获得NB个密文
				cout << "********DN 1 已发送给sgx NB个密文，等待sgx处理！" << endl;
				cnt1 = 0;
				break;
			}
		}


	
}
//获取部分排序好密文
void getSortDN1()
{
		int cn1 = 0;
		int mc1=1;
		sgxdn1 = fopen("../text/sgx_to_DN1.dat", "rb");
		sgxM1 = fopen("../text/sgx_to_DN1M1.txt", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
		
		int j = 0;
		int b = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn1sgx, "%02x", &res[j]) == EOF) {
					b = 1;//判断是否读到文件末尾
					break;
				}
			}
			if (b == 1)
				break;

			cn1++;
			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}

			Sort_DN1[cn1].assign((char*)fres,17);			

		}
		while(1)
		{
			
			if(fscanf(sgxM1, "%d", &M1[mc1])==EOF)
				break;
			mc1++;
		}
		fclose(sgxM1);
		fclose(sgxdn1);

}
//递归寻找每个label的下标
int index1(int i)
{
	if (i == 1)
		return 1;
	else
		return (index1(i - 1) + M1[i - 1]);

}
int index2(int i)
{
	if (i == 1)
		return M1[1];
	else
		return (index2(i - 1) + M1[i]);
}
//收到sgx部分排序好的密文合成按照lable排序好的密文
void Dn1_orderby()
{
	
	getSortDN1();//获得Sort_DN1、M1
	for (int i = 1; i <= M1.size(); i++)
	{
		if (M1[i] != 0)
		{
			for (int j = index1(i); j <= index2(i); j++)
			{
				if (!Sort_DN1[j].empty())
					Label_DN1[i].push_back(Sort_DN1[j]);
			}
		}
	}

}

