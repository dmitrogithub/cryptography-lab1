#include "kccm.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <functional>
#include "interactive.hpp"
#include "overview.hpp"
void run_speed_comparison(bool csv);

static void require(bool condition,const std::string& what) { if(!condition) throw std::runtime_error("ПОМИЛКА: "+what); }
static void rejected(const std::function<void()>& fn,const std::string& name) { bool caught=false; try {fn();} catch(const std::exception&) {caught=true;} require(caught,name); }

static void selftest() {
    const char* aes_expected[]={"69C4E0D86A7B0430D8CDB78070B4C55A","DDA97CA4864CDFE06EAF70A0EC0D7191","8EA2B7CA516745BFEAFC49904B496089"};
    for(size_t i=0;i<3;++i) {
        size_t keybytes=16+8*i; AesTrace aes(sequence(keybytes));
        auto input=unhex("00112233445566778899AABBCCDDEEFF"),cipher=unhex(aes_expected[i]);
        size_t steps=0; auto show=[&](const std::string&,const Bytes&){++steps;};
        require(aes.encrypt(input,show)==cipher&&aes.reference_encrypt(input)==cipher,"покрокове шифрування AES");
        require(aes.decrypt(cipher,show)==input&&AesTrace::reference_decrypt(cipher,sequence(keybytes))==input,"покрокове розшифрування AES");
        require(steps>80,"окремі операції AES");
        std::cout<<"УСПІШНО AES-"<<keybytes*8<<" покрокові пряме й зворотне перетворення\n";
    }
    const size_t bits[]={128,128,256,256,512},keys[]={16,32,32,64,64};
    const char* expected[]={"81BF1C7D779BAC20E1C9EA39B4D2AD06","58EC3E091000158A1148F7166F334F14","F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C","606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9","4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9"};
    for(size_t i=0;i<5;++i) {
        Kalyna k(bits[i],sequence(keys[i])); auto plain=sequence(bits[i]/8,static_cast<unsigned>(keys[i]));
        require(k.encrypt(plain)==unhex(expected[i]),"контрольний вектор Калини"); require(k.decrypt(unhex(expected[i]))==plain,"розшифрування Калини");
        size_t steps=0; require(k.explain(plain,[&](const std::string&,const Bytes&){++steps;})==unhex(expected[i]),"збіг покрокового обчислення з еталоном");
        require(steps==5*k.context()->nr+3,"показ кожної операції раунду");
        size_t reverse_steps=0; require(k.explain_decrypt(unhex(expected[i]),[&](const std::string&,const Bytes&){++reverse_steps;})==plain,"збіг покрокового розшифрування з еталоном");
        require(reverse_steps==5*k.context()->nr+3,"показ кожної зворотної операції раунду");
        std::cout<<"УСПІШНО Калина-"<<bits[i]<<"/"<<keys[i]*8<<" контрольний вектор і розшифрування\n";
    }
    struct Vector {size_t bits,keybytes,nonceStart,plainStart,plainSize,aadStart,aadSize,tag,nb; const char* packet;};
    const Vector vectors[]={
        {128,16,16,48,16,32,16,16,4,"B91A7B8790BBCFCFE65D04E5538E98E2704454C9DD39ADACE0B19D03F6AAB07E"},
        {256,32,32,96,64,64,32,16,4,"7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE809C48AD90A9E12A68380EF1C1B7C83EE1"},
        {256,64,64,128,64,96,32,32,6,"3EBDB4584B5169A26FBEBA0295B4223F58D5D8A031F2950A1D7764FAB97BA058E9E2DAB90FF0C519AA88435155A71B7B53BB100F5D20AFFAC0552F5F2813DEE8DD3653491737B9615A5CCD83DB32F1E479BF227C050325BBBFF60BCA9558D7FE"},
        {512,64,64,192,64,128,64,64,8,"220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99BD8F80CE149143C04FC2490272A31B029DDADA82F055FE4ABEF452A7D438B21E59C1D8B3DD4606BAD66A6F36300EF3CE0E5F3BB59F11416E80B7FC5A8E8B057A"}
    };
    for(auto& v:vectors) {
        Kccm c(v.bits,sequence(v.keybytes),v.tag,v.nb); auto nonce=sequence(v.bits/8,v.nonceStart),aad=sequence(v.aadSize,v.aadStart),plain=sequence(v.plainSize,v.plainStart);
        auto packet=c.seal(nonce,aad,plain); require(packet==unhex(v.packet),"контрольний вектор CCM ДСТУ"); require(c.open(nonce,aad,packet)==plain,"розшифрування CCM");
        size_t events=0; c.set_trace([&](const std::string&,const Bytes&){++events;}); require(c.seal(nonce,aad,plain)==packet&&events>0,"незмінність результату з показом кроків CCM"); c.set_trace({});
        auto bad=packet; bad[0]^=1; rejected([&]{c.open(nonce,aad,bad);},"пошкоджений шифртекст");
        bad=packet; bad.back()^=1; rejected([&]{c.open(nonce,aad,bad);},"пошкоджений тег");
        auto baad=aad; baad[0]^=1; rejected([&]{c.open(nonce,baad,packet);},"пошкоджені AAD");
        auto bn=nonce; bn[0]^=1; rejected([&]{c.open(bn,aad,packet);},"неправильний nonce");
        Kccm wrong(v.bits,Bytes(v.keybytes,0xA5),v.tag,v.nb); rejected([&]{wrong.open(nonce,aad,packet);},"неправильний ключ");
        std::cout<<"УСПІШНО ДСТУ CCM "<<v.bits<<"/"<<v.keybytes*8<<" Nb="<<v.nb<<" вектор, розшифрування та п’ять тестів підміни\n";
    }
    Kccm c(128,sequence(16),16); auto n=sequence(16,16);
    for(size_t count:{size_t(0),size_t(1),size_t(12),size_t(16),size_t(32)}) {
        auto aad=sequence(count); Bytes p(16*300,0); auto packet=c.seal(n,aad,p);
        require(c.open(n,aad,packet)==p,"відновлення довгого повідомлення");
        require(!std::equal(packet.begin(),packet.begin()+16,packet.begin()+256*16),"відсутність повтору лічильника після 256 блоків");
    }
    auto empty=c.seal(n,{},{}); require(c.open(n,{},empty).empty(),"порожнє повідомлення");
    auto n2=n; n2[0]^=1; rejected([&]{c.open(n2,{},empty);},"прив’язка nonce до порожнього повідомлення");
    rejected([&]{c.seal(n,{},Bytes(1));},"неповний блок"); rejected([&]{c.open(n,{},Bytes(1));},"обрізаний тег");
    rejected([&]{Kccm invalid(128,sequence(16),32);},"завеликий тег");
    rejected([&]{unhex("0G");},"некоректний HEX");
    for(size_t length:{size_t(0),size_t(1),size_t(16),size_t(33)}) require(unpad_text(pad_text(sequence(length),16),16)==sequence(length),"додавання та видалення доповнення");
    std::cout<<"УСПІШНО: порожні/короткі/довгі AAD, порожнє повідомлення, лічильник 300 блоків, некоректний ввід\nУСІ ТЕСТИ ПРОЙДЕНО\n";
}
static void demo() {
    auto key=sequence(16),nonce=sequence(16,16),aad=sequence(16,32),plain=sequence(16,48);
    Kccm c(128,key,16); auto packet=c.seal(nonce,aad,plain);
    std::cout<<"Демонстрація CCM ДСТУ 7624 (опубліковані контрольні дані)\nКлюч: "<<hex(key)<<"\nNonce: "<<hex(nonce)<<"\nAAD: "<<hex(aad)<<"\nВідкритий текст: "<<hex(plain)<<"\nШифртекст || тег: "<<hex(packet)<<"\nВідновлено: "<<hex(c.open(nonce,aad,packet))<<"\n";
    std::cout<<"Навмисно змінюємо один біт пакета: очікуємо відмову перевірки.\n";
    packet[0]^=1; try { c.open(nonce,aad,packet); } catch(const std::exception& e) {std::cout<<"Очікуваний результат підміни: "<<e.what()<<"\n";}
}
static void bench(bool localized=false) {
    if(!localized) std::cout<<"algorithm,bytes,seconds,MiB_per_second\n";
    for(size_t bits:{size_t(128),size_t(256),size_t(512)}) {
        auto key=sequence(bits/8),nonce=sequence(bits/8,64); Bytes plain(16384,0x5A); Kccm c(bits,key,16); Kalyna k(bits,key);
        for(bool ccm:{false,true}) { auto start=std::chrono::steady_clock::now(); unsigned checksum=0; const size_t runs=8;
            for(size_t r=0;r<runs;++r) {nonce[0]=static_cast<unsigned char>(r); if(ccm) {auto out=c.seal(nonce,{},plain); checksum+=out.back();} else { for(size_t i=0;i<plain.size();i+=bits/8) {auto out=k.encrypt(Bytes(plain.begin()+i,plain.begin()+i+bits/8)); checksum+=out[0];}} }
            double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
            std::cout<<"Kalyna-reference-"<<bits<<(ccm?"-CCM":"-ECB")<<",";
            if(!localized) std::cout<<plain.size()*runs<<","<<sec<<",";
            std::cout<<(plain.size()*runs/1048576.0/sec)<<"\n"; if(checksum==0) std::cerr<<"checksum=0\n";
        }
    }
}
static void trace() {
    Kalyna k(128,sequence(16)); auto* c=k.context();
    std::cout<<"Раундові ключі Калини 128/128 (порядок байтів як на вході)\n";
    for(size_t r=0;r<=c->nr;++r) { Bytes b(16); std::memcpy(b.data(),c->round_keys[r],16); std::cout<<"K["<<r<<"]="<<hex(b)<<"\n"; }
    std::cout<<"Точки зупинки для налагоджувача: KalynaKeyExpand, KalynaEncipher, SubBytes, ShiftRows, MixColumns.\n";
}
int main(int argc,char** argv) {
    try {
        std::string cmd=argc>1?argv[1]:"menu";
        if(cmd=="menu") {
            for(;;) {
                std::cout<<"\nЛабораторія: Калина, AES та CCM\n1 — Покроково: Калина\n2 — Покроково: AES\n3 — Покроково: CCM із Калиною\n4 — Порівняти швидкість Калини та AES\n0 — Вихід\n";
                if(!std::cin.good()) break;
                auto choice=ask("Вибір: "); if(choice=="0") break;
                try {
                    if(choice=="1"||choice=="2") {
                        auto action=ask("1 — шифрування, 2 — розшифрування [Enter = 1]: ");
                        if(action.empty()) action="1";
                        if(action!="1"&&action!="2") throw std::runtime_error("Виберіть 1 або 2");
                        if(choice=="1") interactive_kalyna_block(action=="2");
                        else interactive_aes(action=="2");
                    } else if(choice=="3") {
                        auto source=ask("1 — навчальні параметри, 2 — власні параметри [Enter = 1]: ");
                        if(source.empty()||source=="1") interactive_encrypt(true,true);
                        else if(source=="2") interactive_encrypt(false,true);
                        else throw std::runtime_error("Виберіть 1 або 2");
                    } else if(choice=="4") {run_speed_comparison(false); bench(true);}
                    else std::cout<<"Введіть номер від 0 до 4.\n";
                }
                catch(const std::exception& e) {std::cout<<"Помилка: "<<e.what()<<"\n"; if(!std::cin.good()) break;}
            }
            return 0;
        }
        if(cmd=="test") selftest(); else if(cmd=="demo") demo(); else if(cmd=="bench") bench(); else if(cmd=="trace") trace();
        else if(cmd=="interactive") interactive_encrypt();
        else if(cmd=="explain") interactive_encrypt(true);
        else if(cmd=="explain-decrypt") interactive_decrypt();
        else if(cmd=="aes-explain") interactive_aes();
        else if(cmd=="aes-explain-decrypt") interactive_aes(true);
        else if(cmd=="kalyna-explain") interactive_kalyna_block();
        else if(cmd=="kalyna-explain-decrypt") interactive_kalyna_block(true);
        else if(cmd=="ccm-explain") interactive_encrypt(true,true);
        else if(cmd=="compare-speed") run_speed_comparison(false);
        else if(cmd=="overview") detailed_overview();
        else if((cmd=="encrypt"||cmd=="decrypt")&&(argc==8||argc==9)) {
            size_t bits=std::stoul(argv[2]),tag=std::stoul(argv[3]),nb=argc==9?std::stoul(argv[8]):4;
            Kccm c(bits,unhex(argv[4]),tag,nb); auto nonce=unhex(argv[5]),aad=unhex(argv[6]),data=unhex(argv[7]);
            std::cout<<hex(cmd=="encrypt"?c.seal(nonce,aad,data):c.open(nonce,aad,data))<<"\n";
        } else { std::cout<<"Використання: kalyna-lab [kalyna-explain|kalyna-explain-decrypt|aes-explain|aes-explain-decrypt|ccm-explain|compare-speed|test]\n"; if(cmd!="help") return 1; }
        return 0;
    } catch(const std::exception& e) {std::cerr<<"Помилка: "<<e.what()<<"\n"; return 1;}
}
