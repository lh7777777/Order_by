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

int NB = 100000;//sgx内存大小

//map<int, string> DN3;//密文
map<long long, string> Sort_DN3;//部分排序好密文
map<int, int> M3;//每个Label数量
int cnt3 = 0;
map<long long, vector<string>> Label_DN3;//按照Label排序好密文
void Dn3_update();//获取密文并按NB个发送给sgx
void Dn3_orderby();//按Label排序好密文并发送给sgx

FILE *cdn;
FILE *dn3sgx;
FILE *sgxdn3;
FILE *sgxM3;
FILE *dn3label;


int a = 0;
int main()
{

	cdn=fopen("../text/c_to_DN3.dat","rb");

	int input = 0;
	int input2=0;
	while (1)
	{
		cout<<"发送DN3密文请输入1："<<endl;
		cin >> input;
		Dn3_update();//接收Client的密文并按照NB发给sgx
		fclose(dn3sgx);
		cout<<"接收Sort_DN3、M3请输入2："<<endl;
		cin >> input2;
		Dn3_orderby();//接收Sort_DN3、M3并存入Label_DN3

		if (a == 1)
		{
			cout << "DN3密文已全部发送完毕,Sort_DN3已全部接收完毕！" << endl<< endl <<endl;
			break;
		}

		//DN3.clear();
		Sort_DN3.clear();
		M3.clear();

	}


	fclose(cdn);

	//发送Lable_DN3给sgx
	int label=0;
	unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
	for (int i = 1; i <= Label_DN3.size(); i++)
	{
		cout<<"发送DN3的Lable "<<i<<" 给sgx，请输入 "<<i<<endl;
		cin>>label;
			//清空输出的文件DN3_to_sgxLabel.dat
			dn3label = fopen("../text/DN3_to_sgxLabel.dat", "wb");//输出Label_DN3[i]

			for (int t = 0; t < Label_DN3[i].size() ; t++)
			{
				fres=(unsigned char*)Label_DN3[i][t].c_str();
				//传一个密文到文件中
				//printf("fres = ");
				for (int i = 0; i < 17; i++)
				{
					//printf("%02x,", fres[i]);
					fprintf(dn3label, "%02x", fres[i]);
					fprintf(dn3label, "\r\n");
				}
				//printf("\n");

			}
			fclose(dn3label);		
	}
	
	return 0;
}

void Dn3_update()
{
		//清空输出的文件DN3_to_sgx.dat
		dn3sgx = fopen("../text/DN3_to_sgx.dat", "wb");

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
				fprintf(dn3sgx, "%02x", fres[i]);
				fprintf(dn3sgx, "\r\n");
			}
			//printf("\n");

			cnt3++;
			
			if (cnt3 == NB)
			{
				//sgx读取文件获得NB个密文
				cout << "********DN 3 已发送给sgx NB个密文，等待sgx处理！" << endl;
				cnt3 = 0;
				break;
			}
		}

	
}

void getSortDN3()
{
		int cn3 = 0;
		int mc3=1;
		sgxdn3 = fopen("../text/sgx_to_DN3.dat", "rb");
		sgxM3 = fopen("../text/sgx_to_DN3M3.txt", "rb");
		unsigned int* res = (unsigned int*)malloc(17 * (sizeof(int)));
		unsigned char* fres = (unsigned char*)malloc(17 * sizeof(char));
		
		int j = 0;
		int b = 0;
		while (1)
		{
			for (j = 0; j < 17; j++) {
				if (fscanf(dn3sgx, "%02x", &res[j]) == EOF) {
					b = 1;//判断是否读到文件末尾
					break;
				}
				//printf("%02x-", res[j]);
			}
			//printf("\n");
			if (b == 1)
				break;

			cn3++;

			
			for (int k = 0; k < 17; k++) {
				fres[k] = res[k];
			}
			/*printf("Sort_DN3[]密文 = ");
			for (int h = 0; h < 17; h++) {
				printf("%c", fres[h]);
			}
			printf("\n");*/

			Sort_DN3[cn3].assign((char*)fres,17);			

		}
		while(1)
		{
			
			if(fscanf(sgxM3, "%d", &M3[mc3])==EOF)
				break;
			//cout << "M3[]：" << M3[mc3]<< endl;
			mc3++;
		}
		fclose(sgxM3);
		fclose(sgxdn3);

}
//递归寻找每个label的下标
int index1(int i)
{
	if (i == 1)
		return 1;
	else
		return (index1(i - 1) + M3[i - 1]);

}
int index2(int i)
{
	if (i == 1)
		return M3[1];
	else
		return (index2(i - 1) + M3[i]);
}
//收到sgx部分排序好的密文合成按照lable排序好的密文
void Dn3_orderby()
{
	
	getSortDN3();//获得Sort_DN3、M3
	for (int i = 1; i <= M3.size(); i++)
	{
		if (M3[i] != 0)
		{
			for (int j = index1(i); j <= index2(i); j++)
			{
				if (!Sort_DN3[j].empty())
					Label_DN3[i].push_back(Sort_DN3[j]);
			}
		}
	}

}

