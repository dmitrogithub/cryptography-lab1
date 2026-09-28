#pragma once
#include "kalyna.hpp"
#include <limits>

// Educational DSTU 7624 CCM implementation, whole-block profile, Nb = 4/6/8.
// Input parameters are explicit; no implicit padding or nonce generation.
class Kccm {
    Kalyna cipher_;
    size_t tag_, nb_;
    Trace trace_;
    void show(const std::string& label,const Bytes& value) { if(trace_) trace_(label,value); }
    static void xor_into(Bytes& a,const Bytes& b) { for(size_t i=0;i<b.size();++i) a[i]^=b[i]; }
    static void put_length(Bytes& b,size_t offset,size_t n,size_t width) { for(size_t i=0;i<width;++i) { b[offset+i]=static_cast<unsigned char>(n&255); n>>=8; } }
    static void increment(Bytes& s) { for(auto& v:s) { if(++v) break; } }
    void validate(const Bytes& nonce,const Bytes& aad,size_t length) {
        if(nonce.size()!=cipher_.block) throw std::runtime_error("Довжина nonce має дорівнювати розміру блока");
        if(length%cipher_.block || (!aad.empty() && aad.size()>cipher_.block-nb_ && aad.size()%cipher_.block)) throw std::runtime_error("Цей профіль CCM потребує цілих блоків повідомлення та коротких AAD або AAD із цілих блоків");
        if(nb_==4 && (length>0xFFFFFFFFULL || aad.size()>0xFFFFFFFFULL)) throw std::runtime_error("Довжина не вміщується в Nb=4");
    }
    Bytes mac(const Bytes& nonce,const Bytes& aad,const Bytes& plain) {
        size_t b=cipher_.block; Bytes g(b,0);
        std::copy_n(nonce.begin(),b-nb_-1,g.begin());
        put_length(g,b-nb_-1,plain.size(),nb_);
        unsigned code=tag_==8?2:tag_==16?3:tag_==32?4:tag_==48?5:6;
        g.back()=static_cast<unsigned char>((aad.empty()?0:128)|(code<<4)|(nb_-1));
        show("CCM / G1: частина nonce | довжина повідомлення | прапорці",g);
        Bytes chain=cipher_.encrypt(g);
        show("CCM / початковий ланцюжок MAC = E(K, G1)",chain);
        auto absorb=[&](const Bytes& part) { show("CCM / наступний блок для MAC",part); xor_into(chain,part); show("CCM / XOR блока з ланцюжком MAC",chain); chain=cipher_.encrypt(chain); show("CCM / новий ланцюжок MAC = E(K, XOR)",chain); };
        if(!aad.empty()) {
            show("CCM / AAD: відкриті дані, захищені тегом",aad);
            Bytes sizes(b,0); put_length(sizes,0,aad.size(),nb_);
            if(aad.size()<=b-nb_) { std::copy(aad.begin(),aad.end(),sizes.begin()+nb_); absorb(sizes); }
            else { absorb(sizes); for(size_t i=0;i<aad.size();i+=b) absorb(Bytes(aad.begin()+i,aad.begin()+i+b)); }
        }
        for(size_t i=0;i<plain.size();i+=b) { show("CCM / блок повідомлення "+std::to_string(i/b+1),Bytes(plain.begin()+i,plain.begin()+i+b)); absorb(Bytes(plain.begin()+i,plain.begin()+i+b)); }
        chain.resize(tag_); show("CCM / MAC до маскування",chain); return chain;
    }
    Bytes crypt(const Bytes& nonce,const Bytes& data,Bytes& mask) {
        Bytes s=cipher_.encrypt(nonce),out(data.size());
        show("CCM / початковий стан лічильника = E(K, nonce)",s);
        for(size_t i=0;i<data.size();i+=cipher_.block) {
            increment(s); show("CCM / лічильник + 1 з перенесенням між байтами",s); Bytes gamma=cipher_.encrypt(s);
            show("CCM / гама = E(K, лічильник)",gamma);
            for(size_t j=0;j<cipher_.block;++j) out[i+j]=data[i+j]^gamma[j];
            show("CCM / блок XOR гама",Bytes(out.begin()+i,out.begin()+i+cipher_.block));
        }
        increment(s); mask=cipher_.encrypt(s); mask.resize(tag_); show("CCM / гама для маскування MAC",mask); return out;
    }
public:
    void set_trace(Trace trace) {trace_=std::move(trace);}
    Kccm(size_t bits,const Bytes& key,size_t tag,size_t nb=4):cipher_(bits,key),tag_(tag),nb_(nb) {
        if((nb!=4&&nb!=6&&nb!=8)||(tag!=8&&tag!=16&&tag!=32&&tag!=48&&tag!=64)||tag>cipher_.block) throw std::runtime_error("Недопустима довжина тега або Nb");
    }
    Bytes seal(const Bytes& nonce,const Bytes& aad,const Bytes& plain) {
        validate(nonce,aad,plain.size()); Bytes tag=mac(nonce,aad,plain),mask;
        Bytes out=crypt(nonce,plain,mask); xor_into(tag,mask); show("CCM / передаваний тег = MAC XOR гама тега",tag); out.insert(out.end(),tag.begin(),tag.end()); return out;
    }
    Bytes open(const Bytes& nonce,const Bytes& aad,const Bytes& packet) {
        if(packet.size()<tag_) throw std::runtime_error("Пакет закороткий для тега");
        validate(nonce,aad,packet.size()-tag_);
        Bytes mask,encrypted(packet.begin(),packet.end()-tag_);
        Bytes plain=crypt(nonce,encrypted,mask),tag=mac(nonce,aad,plain);
        unsigned diff=0; for(size_t i=0;i<tag_;++i) diff|=(tag[i]^mask[i])^packet[encrypted.size()+i];
        if(diff) { std::fill(plain.begin(),plain.end(),0); throw std::runtime_error("Автентифікацію не пройдено: відкритий текст не видано"); }
        return plain;
    }
};
