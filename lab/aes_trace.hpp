#pragma once
#include "kalyna.hpp"
#include <array>

int rijndaelSetupEncrypt(unsigned int*,const unsigned char*,int);
void rijndaelEncrypt(const unsigned int*,int,unsigned char*,unsigned char*);
void rijndaelDecrypt(const unsigned int*,int,const unsigned char*,unsigned char*);
int rijndaelSetupDecrypt(unsigned int*,const unsigned char*,int);

class AesTrace {
    std::array<unsigned int,60> words_{};
    std::array<unsigned char,256> box_{},inverse_{};
    int rounds_;
    static unsigned char gf(unsigned char x,unsigned char y) {
        unsigned char z=0;
        while(y) { if(y&1) z^=x; x=static_cast<unsigned char>((x<<1)^((x&0x80)?0x1B:0)); y>>=1; }
        return z;
    }
    static unsigned char power(unsigned char x,unsigned e) {
        unsigned char z=1; while(e) {if(e&1) z=gf(z,x); x=gf(x,x); e>>=1;} return z;
    }
    static unsigned char rot(unsigned char x,unsigned n) { return static_cast<unsigned char>((x<<n)|(x>>(8-n))); }
    Bytes key(int round) const {
        Bytes b(16);
        for(int col=0;col<4;++col) for(int row=0;row<4;++row)
            b[4*col+row]=static_cast<unsigned char>(words_[4*round+col]>>(24-8*row));
        return b;
    }
    static void xor_key(Bytes& b,const Bytes& k) {for(size_t i=0;i<16;++i) b[i]^=k[i];}
    static void shift(Bytes& b,bool inverse) {
        Bytes old=b;
        for(int col=0;col<4;++col) for(int row=0;row<4;++row)
            b[4*col+row]=old[4*((col+(inverse?4-row:row))%4)+row];
    }
    static void mix(Bytes& b,bool inverse) {
        const unsigned char forward[4][4]={{2,3,1,1},{1,2,3,1},{1,1,2,3},{3,1,1,2}};
        const unsigned char backward[4][4]={{14,11,13,9},{9,14,11,13},{13,9,14,11},{11,13,9,14}};
        Bytes old=b;
        for(int col=0;col<4;++col) for(int row=0;row<4;++row) {
            unsigned char z=0;
            for(int i=0;i<4;++i) z^=gf(old[4*col+i],inverse?backward[row][i]:forward[row][i]);
            b[4*col+row]=z;
        }
    }
public:
    explicit AesTrace(const Bytes& master) {
        if(master.size()!=16&&master.size()!=24&&master.size()!=32) throw std::runtime_error("Ключ AES має містити 16, 24 або 32 байти");
        rounds_=rijndaelSetupEncrypt(words_.data(),master.data(),static_cast<int>(master.size()*8));
        if(rounds_!=10&&rounds_!=12&&rounds_!=14) throw std::runtime_error("Не вдалося розгорнути ключ AES");
        for(int i=0;i<256;++i) {
            auto v=power(static_cast<unsigned char>(i),254);
            box_[i]=static_cast<unsigned char>(v^rot(v,1)^rot(v,2)^rot(v,3)^rot(v,4)^0x63);
            inverse_[box_[i]]=static_cast<unsigned char>(i);
        }
    }
    int rounds() const {return rounds_;}
    Bytes encrypt(const Bytes& input,const Trace& show) const {
        if(input.size()!=16) throw std::runtime_error("AES обробляє один блок із 16 байтів");
        for(int r=0;r<=rounds_;++r) show("Раундовий ключ AES K["+std::to_string(r)+"]",key(r));
        Bytes b=input; show("Вхідний блок AES",b);
        xor_key(b,key(0)); show("Початковий AddRoundKey: XOR з K[0]",b);
        for(int r=1;r<=rounds_;++r) {
            auto p="Раунд "+std::to_string(r)+" / "+std::to_string(rounds_)+": ";
            for(auto& x:b) x=box_[x]; show(p+"SubBytes",b);
            shift(b,false); show(p+"ShiftRows",b);
            if(r!=rounds_) {mix(b,false); show(p+"MixColumns",b);}
            xor_key(b,key(r)); show(p+"AddRoundKey: XOR з K["+std::to_string(r)+"]",b);
        }
        return b;
    }
    Bytes decrypt(const Bytes& input,const Trace& show) const {
        if(input.size()!=16) throw std::runtime_error("AES обробляє один блок із 16 байтів");
        for(int r=0;r<=rounds_;++r) show("Раундовий ключ AES K["+std::to_string(r)+"]",key(r));
        Bytes b=input; show("Вхідний шифртекст AES",b);
        xor_key(b,key(rounds_)); show("Початковий AddRoundKey: XOR з K["+std::to_string(rounds_)+"]",b);
        for(int r=rounds_-1;r>=0;--r) {
            auto p="Зворотний раунд "+std::to_string(r)+": ";
            shift(b,true); show(p+"InvShiftRows",b);
            for(auto& x:b) x=inverse_[x]; show(p+"InvSubBytes",b);
            xor_key(b,key(r)); show(p+"AddRoundKey: XOR з K["+std::to_string(r)+"]",b);
            if(r>0) {mix(b,true); show(p+"InvMixColumns",b);}
        }
        return b;
    }
    Bytes reference_encrypt(const Bytes& input) const {
        if(input.size()!=16) throw std::runtime_error("AES обробляє один блок із 16 байтів");
        Bytes out(16),copy=input; rijndaelEncrypt(words_.data(),rounds_,copy.data(),out.data()); return out;
    }
    static Bytes reference_decrypt(const Bytes& input,const Bytes& master) {
        if(input.size()!=16) throw std::runtime_error("AES обробляє один блок із 16 байтів");
        unsigned int keys[60]{}; int rounds=rijndaelSetupDecrypt(keys,master.data(),static_cast<int>(master.size()*8));
        Bytes out(16); rijndaelDecrypt(keys,rounds,input.data(),out.data()); return out;
    }
};
