#include "aes.h"
//#include <iostream>
//#include <fstream>
#include <string>
#include <string.h>
//#define FILEOPENERROR 1
unsigned char s_box[256] = {
        /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, /*0*/
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, /*1*/
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, /*2*/
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, /*3*/
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, /*4*/
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, /*5*/
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, /*6*/
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, /*7*/
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, /*8*/
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, /*9*/
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, /*a*/
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, /*b*/
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, /*c*/
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, /*d*/
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, /*e*/
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  /*f*/
    };
unsigned char Rcon[4][10] = {
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
    };
unsigned char Inv_S_Box[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

//using namespace std;
Aes::Aes()
{
    //ctor
}

Aes::~Aes()
{
    //dtor
}
/*
*  替换  already test
*/
void Aes::subBytes(unsigned char state[4][4])
{
    int x, y;
    int value;
    for(int i=0 ; i<4 ;i++){//列
        for(int j=0 ; j<4 ;j++){//行
            value = state[j][i];
            x = value / 16 ;
            y = value % 16 ;
            state[j][i] = s_box[x*16+y];
        }
    }
}
/*
*  逆替换   already test
*/
void Aes::invSubBytes(unsigned char state[4][4])
{
    int col,row;
    int x,y;
    int value;
    for(col=0 ; col<4 ; col++){
        for(row=0 ; row<4 ; row++){
            value = state[row][col];
            x = value / 16 ;
            y = value % 16 ;
            state[row][col] = Inv_S_Box[x][y];
        }
    }
}
/*
*  移动行  already test
*/
void Aes::shiftRows(unsigned char state[4][4])
{
    unsigned char temp;
    int times = 0;
    for(int i = 1; i < 4 ; i++)//行
    {
        times = i;
        while(times--)
        {
            temp = state[i][0];//每一行的第一个元素  copy一份
            for(int j = 1 ; j < 4 ; j++)//列
            {
                state[i][j-1] = state[i][j]; //左移一位
            }
            state[i][3] = temp;//填充最后一位
        }
    }
}
/*
*  逆移动行  already test
*/
void Aes::invShiftRows(unsigned char state[4][4])
{
    unsigned char temp;
    int times = 0;
    int i,j;
    for(i = 1; i < 4 ; i++)//行
    {
        times = i;
        while(times--)
        {
            temp = state[i][3];//每一行的第一个元素  copy一份
            for(j=2 ; j>=0 ; j--)//列
            {
                state[i][j+1] = state[i][j]; //左移一位
            }
            state[i][0] = temp;//填充最后一位
        }
    }
}
/*
*  列处理  already test
*/
void Aes::mixColumns(unsigned char state[4][4])
{
    unsigned char copyState[4];
    unsigned char state2[4]; //2倍state
    unsigned char h;
    for(int col=0 ; col<4 ; col++)//列
    {
        //每一列操作
        for(int row=0 ; row<4 ; row++)//行
        {
            copyState[row] = state[row][col];//copy one col state
            h = (unsigned char)((signed char)state[row][col] >> 7);//
            state2[row] = state[row][col] << 1;
            state2[row] ^= 0x1b & h;
        }
        state[0][col] = state2[0] ^ copyState[3] ^ copyState[2] ^ state2[1] ^ copyState[1];/* 2 * a0 + a3 + a2 + 3 * a1 */
        state[1][col] = state2[1] ^ copyState[0] ^ copyState[3] ^ state2[2] ^ copyState[2];/* 2 * a1 + a0 + a3 + 3 * a2 */
        state[2][col] = state2[2] ^ copyState[1] ^ copyState[0] ^ state2[3] ^ copyState[3];/* 2 * a2 + a1 + a0 + 3 * a3 */
        state[3][col] = state2[3] ^ copyState[2] ^ copyState[1] ^ state2[0] ^ copyState[0];/* 2 * a3 + a2 + a1 + 3 * a0 */
    }
}
/*
*  逆列处理   ?????
*/
void Aes::invMixColumns(unsigned char state[4][4])
{
    unsigned char state1[4];//2倍
    unsigned char state2[4];//4倍
    unsigned char state3[4];//8倍
    unsigned char copyState[4];//1倍
    unsigned char h;
    int col,row;
    for(col=0; col<4 ; col++){
        for(row=0 ; row<4 ; row++){
            copyState[row] = state[row][col];
            h = (unsigned char)((signed char)state[row][col] >> 7);//
            state1[row] =  state[row][col] << 1;
            state1[row] ^= 0x1b & h;
            h = (unsigned char)((signed char)state1[row] >> 7);//
            state2[row] =  state1[row] << 1;
            state2[row] ^= 0x1b & h;
            h = (unsigned char)((signed char)state2[row] >> 7);//
            state3[row] =  state2[row] << 1;
            state3[row] ^= 0x1b & h;
        }
        state[0][col] = (state3[0]^state2[0]^state1[0]) ^ (state3[3]^copyState[3]) ^ (state3[2]^state2[2]^copyState[2]) ^ (state3[1]^state1[1]^copyState[1]);/* 14 * a0 + 9 * a3 + 13 * a2 + 11 * a1 */
        state[1][col] = (state3[1]^state2[1]^state1[1]) ^ (state3[0]^copyState[0]) ^ (state3[3]^state2[3]^copyState[3]) ^ (state3[2]^state1[2]^copyState[2]);/* 14 * a1 + 9 * a0 + 13 * a3 + 11 * a2 */
        state[2][col] = (state3[2]^state2[2]^state1[2]) ^ (state3[1]^copyState[1]) ^ (state3[0]^state2[0]^copyState[0]) ^ (state3[3]^state1[3]^copyState[3]);/* 14 * a2 + 9 * a1 + 13 * a0 + 11 * a3 */
        state[3][col] = (state3[3]^state2[3]^state1[3]) ^ (state3[2]^copyState[2]) ^ (state3[1]^state2[1]^copyState[1]) ^ (state3[0]^state1[0]^copyState[0]);/* 14 * a3 + 9 * a2 + 13 * a1 + 11 * a0 */
    }

}
/*
*  异或处理  already test
*/
void Aes::addRoundKey(unsigned char state[4][4], unsigned char roundKey[4][4])// not test
{
    for(int col=0 ; col<4 ; col++){
        for(int row=0 ; row<4 ; row++){
            state[row][col] ^= roundKey[row][col];
        }
    }
}
/*
*  轮密钥生成  already test
*/
void Aes::keySchedule(unsigned char roundKey[4][44])
{
    int colAfter=3;
    unsigned char subCol[4];
    unsigned char downCol[4];
    int x, y;
    int value;
    int t = 0;//轮数  为了使用Rcon
    for(int colBefore=0; colBefore<40 ; colBefore++){//当前轮的列
        if((colAfter+1)%4 == 0){
            //down one bite
            downCol[3] = roundKey[0][colAfter];
            for(int row=1 ; row<4 ;row++){
                downCol[row-1] = roundKey[row][colAfter];
            }
            //sub bytes
            for(int i=0 ; i<4 ;i++){//
                value = downCol[i];
                x = value / 16 ;
                y = value % 16 ;
                subCol[i] = s_box[x*16+y];
            }
            //Xoring
            for(int j=0 ; j<4 ; j++){
                roundKey[j][colAfter+1] = roundKey[j][colBefore] ^ subCol[j] ^ Rcon[j][t];
            }
            t++;
        }else {
            //Xoring
            for(int j=0 ; j<4 ; j++){
                roundKey[j][colAfter+1] = roundKey[j][colBefore] ^ roundKey[j][colAfter];
            }
        }
        colAfter++;
    }//end for
}
/*
*  加密   right
*/
int Aes::encode(unsigned char *pt,unsigned char *ct)
{
    //打开文件
    /*ifstream fileRd(filePath, ios::binary);
    ofstream fileWt("c:\\encode.txt", ios::binary);
    if(fileRd.fail() || fileWt.fail()){//打开失败
        fileRd.close();
        fileWt.close();
        return FILEOPENERROR;
    }
    cout<<"your CIPHERTEXT file will be created at C:\\encode.txt!\n";*/
    //unsigned char buf[16];//取文件内容
    unsigned char state[4][4];//运算状态
    //unsigned char enCdText[16];//加密后的数据
    int t = 0; //计数器
    int i,j;
    int col,row;
    /*bool glap = false;
    while(!fileRd.eof())
    {
        glap = false;
        memset(buf,0x00,16*sizeof(char));//清空buf
        fileRd.read((char *)buf, sizeof(buf));
        //cout<<buf<<endl;
        for(i=0 ; i<16 ; i++)
            if(buf[i] != 0x00){
                glap = true;
                break;
            }
        if(!glap)break;*/
        //buf转化为state
        for(col=0 ; col<4 ; col++)
            for(row=0 ; row<4 ; row++)
                state[row][col] = pt[row+col*4];

        //addRoundkey 第一轮
        addRoundKey(state, roundKey[0]);
        //9轮
        for(i=1 ; i<=9 ;i++){
           subBytes(state);
           shiftRows(state);
           mixColumns(state);
           addRoundKey(state, roundKey[i]);
        }
        //最后一轮
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKey[10]);
        //state 转化为  密文串
        t = 0;
        for(i=0;i<4;i++){
            for(j=0;j<4;j++){
                ct[t++] = state[j][i];
            }
        }
        /*for(i=0 ; i<16 ; i++)
            fileWt.put(enCdText[i]);*/
    //}
    //fileRd.close();
    //fileWt.close();
    return 0;
}
/*
* 解密
*/
int Aes::decode(unsigned char *ct,unsigned char *pt)
{
    //打开文件
    /*ifstream fileRd("c:\\encode.txt", ios::binary);
    ofstream fileWt("c:\\decode.txt", ios::binary);
    if(fileRd.fail() || fileWt.fail()){//打开失败
        fileRd.close();
        fileWt.close();
        return FILEOPENERROR;
    }
    cout<<"Your PLAINTEXT file will be created at C:\\decode.txt!\n";*/
    //unsigned char buf[16];//取文件内容
    unsigned char state[4][4];//运算状态
    //unsigned char deCdText[16];//加密后的数据
    int t = 0; //计数器
    int i,j;
    int col,row;
    //bool glap = false;
    //while(!fileRd.eof())
    //{
        //glap = false;
        //memset(buf,0x00,16*sizeof(char));//清空buf
        //fileRd.read((char *)buf, sizeof(buf));
        //cout<<buf<<endl;
        /*for(i=0 ; i<16 ; i++)
            if(buf[i] != 0x00){
                glap = true;
                break;
            }*/
        //if(!glap)break;
        //buf转化为state
        for(col=0 ; col<4 ; col++)
            for(row=0 ; row<4 ; row++)
                state[row][col] = ct[row+col*4];

        //addRoundkey 第一轮
        addRoundKey(state, roundKey[10]);
        //9轮
        for(i=9 ; i>=1 ;i--){
           invShiftRows(state);
           invSubBytes(state);
           addRoundKey(state, roundKey[i]);
           invMixColumns(state);
        }
        //最后一轮
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKey[0]);
        //state 转化为  密文串
        t = 0;
        for(i=0;i<4;i++){
            for(j=0;j<4;j++){
                pt[t++] = state[j][i];
            }
        }
        /*for(i=0 ; i<16 ; i++)
            fileWt.put(deCdText[i]);*/
    //}
    //fileRd.close();
    //fileWt.close();
    return 0;
}
void Aes::getKey(char *sk)
{
    /*string temp_key;
    bool glap = true;
    int i;
    do{
        cout<<"please input your key(16 characters) : ";
        cin>>temp_key;
        if(temp_key.length() == 16){
            glap = false;
            cout<<"key init success!\n";
        }else {
            glap = true;
            cout<<"key init fail, input again!\n";
        }
    }while(glap);*/
    for(int i=0 ; i<16 ; i++){
        initKey[i] = sk[i];
    }
}

/*void Aes::setFilePath()
{
    char path[30];
    cout<<"input your PLAINTEXT file path : ";
    cin>>path;
    int size = strlen(path);
    filePath = new char(size);
    strcpy(filePath, path);
}*/