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

int N = 100;//数据数量
int NB = 2000;//sgx内存大小
int c = 1;
int m = 0;//Label数量

char sk[17] = { 0 }; //密钥
int sklen = 0;//密钥长度字符数
FILE *fin1,*fin2,*fin3;

void Client_setup(int len);//将sk和m发给sgx
void Client_update(char *pt1, char *sk, int sklen);//加密明文数据并哈希后发送给DN

int main()
{
	//随机生成密钥并设置label对应范围
	//cout << "请输入密钥sk的位数：" << endl;
	int a = 128;//密钥长度位数
	//cin >> a;
	sklen = a / 8;
	Client_setup(sklen);

	//随机生成明文
	//char * flag = NULL;
	//flag = (char*)malloc(N); //将来测试时end设为1000 0000
	//if( NULL == flag )
	//{
	//	perror("memory for flag failed");
	//}
	//memset(flag, 0, N); //初始化为全0	

	map<int,int> flag;
	
	int num;
	int *M = new int[N];
	srand((unsigned)time(NULL));
	/*for (int i = 0; i < N; i++)
	{
		num = rand() % N + 1;
		M[i] = num;
		//cout<<num<<" ";
		for (int j = 0; j < i; j++)
		{
			if (M[j] == M[i])
			{
				i--;
				break;
			}
		}
	}*/

	for(int i = 0; i<N; i++ )
	{
		//一直产生随机数,直到不重复
		while(1)
		{
			num = rand() % N + 1;
			
			if( 0 == flag[num] ) 
			{
				M[i] = num;    //没有重复，把n放入数组
				flag[num] = 1; //已经产生的数,在flag里标记为1
				break ; 
			}
			
		}//退出do while，继续第i+1个随机数
	}
	
	cout<<"生成完毕"<<endl;
	ofstream inputfile;
	inputfile.open("../text/input.txt");
	for (int i = 0; i < N; i++)
	{
		//cout << M[i] << " ";
		inputfile << M[i] << " " ;
	}
	 inputfile << endl;
	 inputfile.close();
	cout << "已生成明文到input.txt中！" << endl;

	//cout<<endl;
	fin1=fopen("../text/c_to_DN1.dat","wb");
	fin2=fopen("../text/c_to_DN2.dat","wb");
	fin3=fopen("../text/c_to_DN3.dat","wb");
	for (int i = 0; i < N; i++)
	{
		char pt1[17] = { 0 };//每一个明文数字
		//itoa(M[i], pt1, 10);
		sprintf(pt1, "%d", M[i]);//明文int转化为char
		//cout << "明文：" << pt1 << " ";
		Client_update(pt1, sk, sklen);
	}

	fclose(fin1);
	fclose(fin2);
	fclose(fin3);
	cout<<"密文已哈希发送给三个DN！"<<endl;
	return 0;
}

//随机生成AES密钥
void GenerateAESKey(char* key, int len)
{
	const char CCH[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	srand((unsigned)time(NULL));
	for (int i = 0; i < len; ++i)
	{
		int x = rand() / (RAND_MAX / (sizeof(CCH) - 1));

		key[i] = CCH[x];
	}
}
void Client_setup(int len)
{
	GenerateAESKey(sk, len);// 128bits key
	cout << "AES密钥为：" << sk << endl;
	if(N<=NB)
		m=1;
	else
		m = c * ceil(N / NB);
	cout << "label数量为：" << m << endl;
	ofstream outfile;
	outfile.open("../text/c_to_sgx.txt");
	outfile << sk << " " << m << endl;
	outfile.close();
	cout<<"密钥和Label数量已发送给sgx！"<<endl;
}

//16进制转10进制
int hex_char_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return 0;
}
int hex_to_decimal(const char* szHex, int len)
{
	int result = 0;
	for (int i = 0; i < len; i++)
	{
		result += (int)pow((float)16, (int)len - i - 1) * hex_char_value(szHex[i]);
	}
	return result;
}

//字符串转换成16进制
inline char *CharArrayToHexString(char* pOut, const int nMaxLen, const char* pInput, const int nInLen)
{
    const char* chHexList = "0123456789ABCDEF";
    int nIndex = 0;
    int i=0, j=0;
    for (i=0, j=0;i<nInLen;i++, j+=2)
    {
        nIndex = (pInput[i] & 0xf);
        pOut[i*2+1] = chHexList[nIndex];
        nIndex = ((pInput[i]>>4) & 0xf);
        pOut[i*2] = chHexList[nIndex];
    }
    return pOut;
}
//16进制转换成字符串
inline char *HexStringToCharArray(char* pOut, const char* pInput, const int nInLen)
{
    int i=0;
    int tc;    
    for (i = 0; i < nInLen/2 ; i++)
    {
        sscanf(pInput+i*2, "%02X", (unsigned int*)(pOut+i));
    }
    pOut[i] = '\0';
    return pOut;
}

void Client_update(char *pt1, char *sk, int sklen)
{
	unsigned char ct[17] = { 0 }; // 每一个AES密文
	AES_KEY k;

	//AES加密

	AES_set_encrypt_key((unsigned char*)sk, sklen * 8, &k);
	AES_encrypt((unsigned char*)pt1, (unsigned char*)ct, &k);

	//MD5哈希
	char ct2[17] = { 0 }; // 每一个AES密文
	strcpy(ct2, (char*)ct);
	unsigned char mdStr[33] = { 0 };// 哈希后的字符串
	MD5((const unsigned char *)ct2, strlen(ct2), mdStr);
	char buf[65] = { 0 };
	char tmp[3] = { 0 };
	for (int i = 0; i < 32; i++)
	{
		sprintf(tmp, "%02x", mdStr[i]);
		strcat(buf, tmp);
	}
	buf[32] = '\0'; // 后面都是0，从32字节截断
	int dec = hex_to_decimal(buf, 6);//取6位进行取模哈希

	//哈希到3个DN中

	if (dec % 3 == 0)
	{

    		//printf("ct = ");
    		for(int i = 0; i < 17; i++)
    		{
        		//printf("%02x,", ct[i]);
        		fprintf(fin1, "%02x", ct[i]);//以16进制形式写入文件（避免密文中存在0x00写不进去的问题）
       		 	fprintf(fin1, "\r\n");
    		}
    		//printf("\n");
    		

	}
	else if (dec % 3 == 1)
	{
		//printf("ct = ");
    		for(int i = 0; i < 17; i++)
    		{
        		//printf("%02x,", ct[i]);
        		fprintf(fin2, "%02x", ct[i]);
       		 	fprintf(fin2, "\r\n");
    		}
    		//printf("\n");
		
	}
	else if (dec % 3 == 2)
	{
		//printf("ct = ");
    		for(int i = 0; i < 17; i++)
    		{
        		//printf("%02x,", ct[i]);
        		fprintf(fin3, "%02x", ct[i]);
       		 	fprintf(fin3, "\r\n");
    		}
    		//printf("\n");
		
	}
}

