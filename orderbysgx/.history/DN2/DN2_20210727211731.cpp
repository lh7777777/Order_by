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

int NB = 4000;

//map<int, string> DN2;
map<int, string> Sort_DN2;//部分排序好密文
map<int, int> M2;//每个Label数量
int cnt2 = 0;
map<int, vector<string>> Label_DN2;//按照Label排序好密文
void Dn2_update();//获取密文并按NB个发送给sgx
void Dn2_orderby();//按Label排序好密文并发送给sgx

FILE *cdn;
FILE *dn2sgx;
FILE *sgxdn2;
FILE *sgxM2;
FILE *dn2label;

int a = 0;
int main()
{

	cdn=fopen("../text/c_to_DN2.dat","rb");

	int input = 0;
	int input2=0;
	while (1)
	{
		cout<<"发送DN2密文请输入1："<<endl;
		cin >> input;
		Dn2_update();//接收Client的密文并按照NB发给sgx
		fclose(dn2sgx);
		cout<<"接收Sort_DN2、M2请输入2："<<endl;
		cin >> input2;
		Dn2_orderby();//接收Sort_DN2、M2并存入Label_DN2

		if (a == 1)
		{
			cout << "DN2密文已全部发送完毕,Sort_DN2已全部接收完毕！" << endl<< endl <<endl;

			break;
		}

		//DN2.clear();
		Sort_DN2.clear();
		M2.clear();

	}


	fclose(cdn);

	//发送Lable_DN2给sgx
	int label=0;
	unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
	for (int i = 1; i <= Label_DN2.size(); i++)
	{
		cout<<"发送DN2的Lable "<<i<<" 给sgx，请输入 "<<i<<endl;
		cin>>label;
			//清空输出的文件DN2_to_sgxLabel.dat
			dn2label = fopen("../text/DN2_to_sgxLabel.dat", "wb");//输出Label_DN2[i]

			for (int t = 0; t < Label_DN2[i].size() ; t++)
			{
				fres=(unsigned char*)Label_DN2[i][t].c_str();
				//传一个密文到文件中
				//printf("fres = ");
				for (int i = 0; i < 17; i++)
				{
					//printf("%02x,", fres[i]);
					fprintf(dn2label, "%02x", fres[i]);
					fprintf(dn2label, "\r\n");
				}
				//printf("\n");

			}
			fclose(dn2label);		
	}
	
	return 0;
}

void Dn2_update()
{
	
		//清空输出的文件DN2_to_sgx.dat
		dn2sgx = fopen("../text/DN2_to_sgx.dat", "wb");

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
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (a == 1)
				break;
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			/*printf("fres密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");*/

			//传一个密文到文件中
			//printf("fres = ");
			for (int i = 0; i < 17; i++)
			{
				//printf("%02x,", fres[i]);
				fprintf(dn2sgx, "%02x", fres[i]);
				fprintf(dn2sgx, "\r\n");
			}
			//printf("\n");

			cnt2++;
			
			if (cnt2 == NB)
			{
				//sgx读取文件获得NB个密文
				cout << "********DN 2 已发送给sgx NB个密文，等待sgx处理！" << endl;
				cnt2 = 0;
				break;
			}
		}


	
}

void getSortDN2()
{
		int cn2 = 0;
		int mc2=1;
		sgxdn2 = fopen("../text/sgx_to_DN2.dat", "rb");
		sgxM2 = fopen("../text/sgx_to_DN2M2.txt", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
		
		int j = 0;
		int b = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn2sgx, "%02x", &res[j]) == EOF) {
					b = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (b == 1)
				break;

			cn2++;

			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			/*printf("Sort_DN2[]密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");*/

			Sort_DN2[cn2].assign((char*)fres,17);			

		}
		while(1)
		{
			
			if(fscanf(sgxM2, "%d", &M2[mc2])==EOF)
				break;
			//cout << "M2[]：" << M2[mc2]<< endl;
			mc2++;
		}
		fclose(sgxM2);
		fclose(sgxdn2);

}
//递归寻找每个label的下标
int index1(int i)
{
	if (i == 1)
		return 1;
	else
		return (index1(i - 1) + M2[i - 1]);

}
int index2(int i)
{
	if (i == 1)
		return M2[1];
	else
		return (index2(i - 1) + M2[i]);
}
//收到sgx部分排序好的密文合成按照lable排序好的密文
void Dn2_orderby()
{
	
	getSortDN2();//获得Sort_DN2、M2
	for (int i = 1; i <= M2.size(); i++)
	{
		if (M2[i] != 0)
		{
			for (int j = index1(i); j <= index2(i); j++)
			{
				if (!Sort_DN2[j].empty())
					Label_DN2[i].push_back(Sort_DN2[j]);
			}
		}
	}

}

