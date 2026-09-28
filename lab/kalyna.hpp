#pragma once
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <functional>
extern "C" {
#include "kalyna.h"
#include "transformations.h"
}
using Bytes = std::vector<unsigned char>;
using Trace = std::function<void(const std::string&,const Bytes&)>;

inline Bytes unhex(const std::string& s) {
    if(s == "-") return {};
    if(s.size()%2) throw std::runtime_error("HEX має містити парну кількість цифр");
    Bytes b;
    auto digit=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; throw std::runtime_error("Некоректна цифра HEX"); };
    for(size_t i=0;i<s.size();i+=2) b.push_back(static_cast<unsigned char>((digit(s[i])<<4)|digit(s[i+1])));
    return b;
}
inline std::string hex(const Bytes& b) { const char* h="0123456789ABCDEF"; std::string s; for(auto x:b) { s+=h[x>>4]; s+=h[x&15]; } return s; }
inline Bytes sequence(size_t n, unsigned int start=0) { Bytes b(n); for(size_t i=0;i<n;++i) b[i]=static_cast<unsigned char>(start+i); return b; }

class Kalyna {
    kalyna_t* ctx_;
public:
    const size_t block;
    Kalyna(size_t bits, const Bytes& key):ctx_(nullptr),block(bits/8) {
        if(!((bits==128&&(key.size()==16||key.size()==32))||(bits==256&&(key.size()==32||key.size()==64))||(bits==512&&key.size()==64))) throw std::runtime_error("Недопустиме поєднання розміру блока та ключа Калини");
        ctx_=KalynaInit(bits,key.size()*8);
        if(!ctx_) throw std::runtime_error("Не вдалося ініціалізувати Калину");
        uint64_t words[8]={}; std::memcpy(words,key.data(),key.size()); KalynaKeyExpand(words,ctx_);
    }
    ~Kalyna(){KalynaDelete(ctx_);}
    Kalyna(const Kalyna&)=delete;
    Kalyna& operator=(const Kalyna&)=delete;
    Bytes encrypt(const Bytes& in) { return transform(in,false); }
    Bytes explain(const Bytes& in,const Trace& show) {
        if(in.size()!=block) throw std::runtime_error("Очікується один повний блок");
        auto state=[&](const std::string& label) { Bytes b(block); std::memcpy(b.data(),ctx_->state,block); show(label,b); };
        for(size_t r=0;r<=ctx_->nr;++r) { Bytes b(block); std::memcpy(b.data(),ctx_->round_keys[r],block); show("Раундовий ключ K["+std::to_string(r)+"]",b); }
        std::memcpy(ctx_->state,in.data(),block); state("Вхідний блок");
        AddRoundKey(0,ctx_); state("Початкове додавання з K[0] за модулем 2^64");
        for(size_t r=1;r<=ctx_->nr;++r) {
            std::string prefix="Раунд "+std::to_string(r)+" / "+std::to_string(ctx_->nr)+": ";
            SubBytes(ctx_); state(prefix+"SubBytes — заміна байтів за S-блоками");
            ShiftRows(ctx_); state(prefix+"ShiftRows — циклічний зсув рядків");
            MixColumns(ctx_); state(prefix+"MixColumns — перемішування стовпців в GF(2^8)");
            if(r==ctx_->nr) { AddRoundKey(static_cast<int>(r),ctx_); state(prefix+"фінальне додавання з ключем за модулем 2^64"); }
            else { XorRoundKey(static_cast<int>(r),ctx_); state(prefix+"XOR з раундовим ключем"); }
        }
        Bytes out(block); std::memcpy(out.data(),ctx_->state,block); return out;
    }
    Bytes decrypt(const Bytes& in) { return transform(in,true); }
    Bytes explain_decrypt(const Bytes& in,const Trace& show) {
        if(in.size()!=block) throw std::runtime_error("Очікується один повний блок шифртексту");
        auto state=[&](const std::string& label) { Bytes b(block); std::memcpy(b.data(),ctx_->state,block); show(label,b); };
        for(size_t r=0;r<=ctx_->nr;++r) { Bytes b(block); std::memcpy(b.data(),ctx_->round_keys[r],block); show("Раундовий ключ K["+std::to_string(r)+"]",b); }
        std::memcpy(ctx_->state,in.data(),block); state("Вхідний шифртекст");
        SubRoundKey(static_cast<int>(ctx_->nr),ctx_); state("Віднімання K["+std::to_string(ctx_->nr)+"] за модулем 2^64");
        for(size_t r=ctx_->nr;r>0;--r) {
            std::string prefix="Зворотний раунд "+std::to_string(r)+" / "+std::to_string(ctx_->nr)+": ";
            InvMixColumns(ctx_); state(prefix+"InvMixColumns — зворотне перемішування стовпців");
            InvShiftRows(ctx_); state(prefix+"InvShiftRows — зворотний зсув рядків");
            InvSubBytes(ctx_); state(prefix+"InvSubBytes — зворотна заміна байтів");
            if(r>1) { XorRoundKey(static_cast<int>(r-1),ctx_); state(prefix+"XOR з K["+std::to_string(r-1)+"]"); }
        }
        SubRoundKey(0,ctx_); state("Початковий блок: віднімання K[0] за модулем 2^64");
        Bytes out(block); std::memcpy(out.data(),ctx_->state,block); return out;
    }
    Bytes transform(const Bytes& in,bool dec) {
        if(in.size()!=block) throw std::runtime_error("Очікується один повний блок");
        uint64_t a[8]={},b[8]={}; std::memcpy(a,in.data(),block);
        if(dec) KalynaDecipher(a,ctx_,b); else KalynaEncipher(a,ctx_,b);
        Bytes out(block); std::memcpy(out.data(),b,block); return out;
    }
    kalyna_t* context(){return ctx_;}
};
