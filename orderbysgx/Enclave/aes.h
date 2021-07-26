#ifndef AES_H
#define AES_H
#include <string.h>
//#include <fstream>

//using namespace std;

class Aes
{
    public:
        Aes();
        virtual ~Aes();
        void subBytes(unsigned char state[4][4]);
        void shiftRows(unsigned char state[4][4]);
        void mixColumns(unsigned char state[4][4]);
        void invSubBytes(unsigned char state[4][4]);
        void invShiftRows(unsigned char state[4][4]);
        void invMixColumns(unsigned char state[4][4]);
        void addRoundKey(unsigned char state[4][4], unsigned char roundKey[4][4]);
        void keySchedule(unsigned char roundKey[4][44]);
        void getKey(char *sk);
        int encode(unsigned char *pt,unsigned char *ct);
        int decode(unsigned char *ct,unsigned char *pt);
        //void setFilePath();
        void setRoundKey(unsigned char* key)
        {
            for(int col=0 ; col<4 ; col++)
                for(int row=0 ; row<4 ; row++)
                    roundKey_temp[row][col] = key[row+col*4];
        }
        void initAes()
        {
            setRoundKey(initKey);
            keySchedule(roundKey_temp);
            for(int col=0 ; col<44 ; col++)
                for(int row=0 ; row<4 ; row++)
                    roundKey[col/4][row][col%4] = roundKey_temp[row][col];
        }
    private:
        //char *filePath;
        unsigned char roundKey_temp[4][44];
        unsigned char roundKey[11][4][4];
        unsigned char initKey[16];
};

#endif // AES_H