#pragma once
#include "kccm.hpp"
#include "aes_trace.hpp"
#include <iostream>
#include <iomanip>
#include <random>
#include <cctype>

inline std::string ask(const std::string& label) {
    std::cout<<label<<std::flush; std::string s;
    if(!std::getline(std::cin,s)) throw std::runtime_error("Введення завершено");
    return s;
}
inline Bytes spaced_hex(std::string s) {
    s.erase(std::remove_if(s.begin(),s.end(),[](unsigned char c){return std::isspace(c);}),s.end());
    return unhex(s);
}
inline Bytes random_bytes(size_t n) { std::random_device rng; Bytes b(n); for(auto& x:b) x=static_cast<unsigned char>(rng()); return b; }
inline Bytes pad_text(Bytes b,size_t block) { auto n=static_cast<unsigned char>(block-b.size()%block); b.insert(b.end(),n,n); return b; }
inline Bytes unpad_text(Bytes b,size_t block) {
    if(b.empty()||b.size()%block||!b.back()||b.back()>block||b.back()>b.size()) throw std::runtime_error("Некоректне доповнення тексту");
    size_t n=b.back(); for(size_t i=b.size()-n;i<b.size();++i) if(b[i]!=n) throw std::runtime_error("Некоректне доповнення тексту");
    b.resize(b.size()-n); return b;
}
inline void algorithm_map() {
    std::cout<<"\nКАЛИНА — блоковий шифр\n"
      "  Ключ -> розгортання -> K[0], K[1], ... K[N]\n"
      "  Блок -> (+ K[0]) -> раунди -> зашифрований блок\n"
      "  Раунд: SubBytes -> ShiftRows -> MixColumns -> XOR K[r]\n"
      "  В останньому раунді замість XOR: додавання за модулем 2^64.\n"
      "  SubBytes: кожен байт замінюється за однією з чотирьох таблиць.\n"
      "  ShiftRows: рядки матриці циклічно зсуваються.\n"
      "  MixColumns: байти стовпця перемішуються множенням в GF(2^8).\n"
      "  XOR: 0^0=0, 0^1=1, 1^0=1, 1^1=0.\n"
      "  Додавання: окремо для кожного 64-бітного слова, переповнення відкидається.\n"
      "  Блок/ключ: 128/128, 128/256, 256/256, 256/512, 512/512 біт.\n"
      "  Кількість раундів за довжиною ключа: 10, 14 або 18.\n\n"
      "CCM — режим використання Калини\n"
      "  nonce + довжина + AAD + повідомлення -> CBC-MAC -> MAC\n"
      "  nonce -> E(K, nonce) -> лічильник -> E(K, лічильник) -> гама\n"
      "  повідомлення XOR гама -> шифртекст\n"
      "  MAC XOR наступна гама -> передаваний тег\n"
      "  Результат: шифртекст || тег. AAD не шифрується.\n"
      "  Під час розшифрування тег перевіряється до видачі тексту.\n\n";
}
inline Trace display_steps(bool matrix,bool pause) {
    return [matrix,pause,step=size_t(0)](const std::string& label,const Bytes& value) mutable {
        std::cout<<"\n[Крок "<<++step<<"] "<<label<<"\nHEX: "<<hex(value)<<"\n";
        if(matrix) {
            const size_t cols=value.size()/8;
            std::cout<<"Матриця стану: 8 рядків x "<<cols<<" стовпців; байти заповнюють стовпці\n";
            for(size_t row=0;row<8;++row) {
                std::cout<<"  "; for(size_t col=0;col<cols;++col) { auto byte=value[row+8*col]; std::cout<<std::hex<<std::uppercase<<std::setw(2)<<std::setfill('0')<<unsigned(byte)<<" "; }
                std::cout<<std::dec<<std::setfill(' ')<<"\n";
            }
        }
        if(pause) ask("Enter — наступний крок...");
    };
}
inline Trace display_aes_steps(bool pause) {
    return [pause,step=size_t(0)](const std::string& label,const Bytes& value) mutable {
        std::cout<<"\n[Крок "<<++step<<"] "<<label<<"\nHEX: "<<hex(value)<<"\nМатриця AES: 4 рядки x 4 стовпці; байти заповнюють стовпці\n";
        for(size_t row=0;row<4;++row) {
            std::cout<<"  ";
            for(size_t col=0;col<4;++col)
                std::cout<<std::hex<<std::uppercase<<std::setw(2)<<std::setfill('0')<<unsigned(value[4*col+row])<<" ";
            std::cout<<std::dec<<std::setfill(' ')<<"\n";
        }
        if(pause) ask("Enter — наступний крок...");
    };
}
inline void interactive_kalyna_block(bool inverse=false) {
    std::cout<<"\nПокрокове "<<(inverse?"розшифрування":"шифрування")<<" базовою Калиною (блоки ECB, без CCM).\n";
    auto b=ask("Розмір блока: 128, 256 або 512 [Enter = 128]: ");
    if(b.empty()) b="128";
    if(b!="128"&&b!="256"&&b!="512") throw std::runtime_error("Виберіть 128, 256 або 512");
    size_t bits=std::stoul(b),block=bits/8;
    auto k=ask("Основний ключ у HEX [Enter = 00..0F для 128 біт]: ");
    Bytes key=k.empty()?sequence(block):spaced_hex(k);
    Kalyna kalyna(bits,key);
    Bytes input;
    if(inverse) input=spaced_hex(ask("Шифртекст у HEX (цілі блоки): "));
    else {
        auto mode=ask("Дані: 1 — звичайний текст, 2 — HEX [Enter = 1]: ");
        if(mode.empty()||mode=="1") {
            auto message=ask("Введіть текст [Enter = Hello world!]: ");
            if(message.empty()) message="Hello world!";
            input=Bytes(message.begin(),message.end());
            std::cout<<"Текст у UTF-8: "<<message<<"\nБайти у HEX: "<<hex(input)<<"\n";
            auto length=input.size(); input=pad_text(input,block);
            std::cout<<"Додано "<<input.size()-length<<" байт PKCS#7; після доповнення: "<<hex(input)<<"\n";
        } else if(mode=="2") input=spaced_hex(ask("Відкритий текст у HEX (цілі блоки): "));
        else throw std::runtime_error("Виберіть 1 або 2");
    }
    if(input.empty()||input.size()%block||input.size()>1024) throw std::runtime_error("Потрібні цілі блоки, максимум 1024 байти");
    bool pause=ask("Зупинятися після кожного кроку? 1 — так [Enter = весь процес одразу]: ")=="1";
    std::cout<<"\nОсновний ключ: "<<hex(key)<<"\n";
    Bytes output;
    for(size_t i=0;i<input.size();i+=block) {
        Bytes part(input.begin()+i,input.begin()+i+block);
        std::cout<<"\n=== Блок "<<i/block+1<<" / "<<input.size()/block<<" ===\n";
        auto result=inverse?kalyna.explain_decrypt(part,display_steps(true,pause)):kalyna.explain(part,display_steps(true,pause));
        if(inverse) {
            if(result!=kalyna.decrypt(part)||kalyna.encrypt(result)!=part) throw std::runtime_error("Зворотний розбір не збігся з еталонною Калиною");
        } else if(result!=kalyna.encrypt(part)) throw std::runtime_error("Прямий розбір не збігся з еталонною Калиною");
        output.insert(output.end(),result.begin(),result.end());
    }
    std::cout<<"\nРЕЗУЛЬТАТ КАЛИНИ\n"<<(inverse?"Відновлено (HEX): ":"Шифртекст: ")<<hex(output)<<"\nПеревірка за еталонною реалізацією: УСПІШНО\n";
    if(inverse) {
        try {
            auto original=unpad_text(output,block);
            std::cout<<"Після зняття PKCS#7 (HEX): "<<hex(original)<<"\n";
            std::cout<<"Відновлений текст: "<<std::string(original.begin(),original.end())<<"\n";
        } catch(const std::runtime_error&) {std::cout<<"Доповнення PKCS#7 відсутнє; показано всі байти.\n";}
    }
}
inline void interactive_aes(bool inverse=false) {
    std::cout<<"\nПокрокове "<<(inverse?"розшифрування":"шифрування")<<" AES (навчальний ECB, без CCM).\n";
    auto k=ask("Ключ AES у HEX: 16, 24 або 32 байти [Enter = 00..0F]: ");
    Bytes key=k.empty()?sequence(16):spaced_hex(k);
    AesTrace aes(key);
    Bytes input;
    if(inverse) {
        auto v=ask("Шифртекст у HEX (цілі блоки) [Enter = контрольний блок FIPS 197]: ");
        input=v.empty()?unhex("69C4E0D86A7B0430D8CDB78070B4C55A"):spaced_hex(v);
    } else {
        auto mode=ask("Дані: 1 — звичайний текст, 2 — HEX [Enter = 1]: ");
        if(mode.empty()||mode=="1") {
            auto message=ask("Введіть текст [Enter = Hello world!]: ");
            if(message.empty()) message="Hello world!";
            input=Bytes(message.begin(),message.end());
            std::cout<<"Текст у UTF-8: "<<message<<"\nБайти у HEX: "<<hex(input)<<"\n";
            auto length=input.size(); input=pad_text(input,16);
            std::cout<<"Додано "<<input.size()-length<<" байт PKCS#7; після доповнення: "<<hex(input)<<"\n";
        } else if(mode=="2") {
            auto v=ask("Відкритий текст у HEX [Enter = 00112233445566778899AABBCCDDEEFF]: ");
            input=v.empty()?unhex("00112233445566778899AABBCCDDEEFF"):spaced_hex(v);
        } else throw std::runtime_error("Виберіть 1 або 2");
    }
    if(input.empty()||input.size()%16||input.size()>1024) throw std::runtime_error("Введіть від 1 до 64 повних блоків AES (по 16 байтів)");
    bool pause=ask("Зупинятися після кожного кроку? 1 — так [Enter = весь процес одразу]: ")=="1";
    std::cout<<"\nОсновний ключ: "<<hex(key)<<"\nКількість раундів: "<<aes.rounds()<<"\n";
    Bytes output;
    for(size_t i=0;i<input.size();i+=16) {
        Bytes block(input.begin()+i,input.begin()+i+16);
        std::cout<<"\n=== Блок "<<i/16+1<<" / "<<input.size()/16<<" ===\n";
        auto result=inverse?aes.decrypt(block,display_aes_steps(pause)):aes.encrypt(block,display_aes_steps(pause));
        if(inverse) {
            if(result!=AesTrace::reference_decrypt(block,key)||aes.reference_encrypt(result)!=block) throw std::runtime_error("Покрокове розшифрування AES не збіглося з реалізацією з ciphers-speed");
        } else if(result!=aes.reference_encrypt(block)) throw std::runtime_error("Покрокове шифрування AES не збіглося з реалізацією з ciphers-speed");
        output.insert(output.end(),result.begin(),result.end());
    }
    std::cout<<"\nРЕЗУЛЬТАТ AES\n"<<(inverse?"Відновлений блок/блоки: ":"Шифртекст: ")<<hex(output)<<"\nПеревірка за реалізацією з ciphers-speed: УСПІШНО\n";
    if(inverse) {
        try {
            auto unpadded=unpad_text(output,16);
            std::cout<<"Після зняття PKCS#7 (HEX): "<<hex(unpadded)<<"\n";
            std::cout<<"Текст після зняття PKCS#7: "<<std::string(unpadded.begin(),unpadded.end())<<"\n";
        } catch(const std::runtime_error&) { std::cout<<"Доповнення PKCS#7 відсутнє; показано всі байти блока.\n"; }
    }
}
inline void interactive_decrypt() {
    std::cout<<"\nПокрокове розшифрування одного блока Калини (ECB, без CCM).\n";
    auto b=ask("Розмір блока: 128, 256 або 512 [Enter = 128]: ");
    if(b.empty()) b="128";
    if(b!="128"&&b!="256"&&b!="512") throw std::runtime_error("Виберіть 128, 256 або 512");
    size_t bits=std::stoul(b);
    auto cipher=spaced_hex(ask("Шифртекст одного блока у HEX: "));
    if(cipher.size()!=bits/8) throw std::runtime_error("Шифртекст має містити рівно один блок: "+std::to_string(bits/8)+" байт");
    auto key=spaced_hex(ask("Основний ключ у HEX: "));
    Kalyna k(bits,key);
    bool pause=ask("Зупинятися після кожного кроку? 1 — так [Enter = весь процес одразу]: ")=="1";
    auto plain=k.explain_decrypt(cipher,display_steps(true,pause));
    if(plain!=k.decrypt(cipher)||k.encrypt(plain)!=cipher) throw std::runtime_error("Покрокове розшифрування не збіглося з еталоном");
    std::cout<<"\nВідновлений блок (HEX): "<<hex(plain)<<"\n";
    if(std::all_of(plain.begin(),plain.end(),[](unsigned char ch){return ch>=0x20&&ch<=0x7E;}))
        std::cout<<"Відновлений блок (ASCII): "<<std::string(plain.begin(),plain.end())<<"\n";
    std::cout<<"Перевірка повторним шифруванням: УСПІШНО\n";
}
inline void interactive_encrypt(bool fixed=false,bool ccm_only=false) {
    size_t bits=128; Bytes key,nonce,aad,plain; bool textMode=false;
    if(fixed) {
        key=sequence(16); nonce=sequence(16,16); aad=sequence(16,32);
        std::cout<<"\nПокроковий розбір із навчальними параметрами: блок 128 біт, ключ 00..0F, nonce 10..1F, AAD 20..2F.\nФіксовані ключ і nonce призначені лише для навчальних прикладів.\n";
        auto source=ask("Що шифрувати? 1 — контрольний приклад, 2 — власний текст [Enter = 2]: ");
        if(source=="1") plain=sequence(16,48);
        else if(source.empty()||source=="2") {
            auto msg=ask("Введіть текст [Enter = Hello world! This is Kalyna CCM.]: ");
            if(msg.empty()) msg="Hello world! This is Kalyna CCM.";
            if(msg.size()>1024) throw std::runtime_error("Для наочної демонстрації максимум 1024 байти");
            textMode=true; plain=Bytes(msg.begin(),msg.end());
            std::cout<<"\nВідкритий текст: "<<msg<<"\nUTF-8 у HEX: "<<hex(plain)<<"\n";
            auto original=plain.size(); plain=pad_text(plain,bits/8);
            std::cout<<"Довжина UTF-8: "<<original<<" байт. Додано "<<plain.size()-original<<" байт PKCS#7.\nПісля доповнення: "<<plain.size()<<" байт, блоків: "<<plain.size()/(bits/8)<<".\n";
            for(size_t i=0;i<plain.size();i+=bits/8)
                std::cout<<"Блок "<<i/(bits/8)+1<<": "<<hex(Bytes(plain.begin()+i,plain.begin()+i+bits/8))<<"\n";
        } else throw std::runtime_error("Виберіть 1 або 2");
    }
    else {
        std::cout<<"\nВласні дані. Порожній ключ і nonce — створити випадкові.\n";
        auto b=ask("Розмір блока: 128, 256 або 512 [Enter = 128]: ");
        if(!b.empty()) { if(b!="128"&&b!="256"&&b!="512") throw std::runtime_error("Виберіть 128, 256 або 512"); bits=std::stoul(b); }
        auto k=ask("Ключ у HEX [Enter = випадковий ключ довжини блока]: "); key=k.empty()?random_bytes(bits/8):spaced_hex(k);
        Kalyna check(bits,key);
        auto n=ask("Nonce у HEX [Enter = новий випадковий]: "); nonce=n.empty()?random_bytes(bits/8):spaced_hex(n);
        if(nonce.size()!=bits/8) throw std::runtime_error("Довжина nonce має збігатися з довжиною блока");
        auto mode=ask("Повідомлення: 1 — звичайний текст, 2 — HEX [Enter = 1]: ");
        if(mode!=""&&mode!="1"&&mode!="2") throw std::runtime_error("Виберіть 1 або 2");
        textMode=mode!="2"; auto msg=ask(textMode?"Введіть текст: ":"Введіть HEX повідомлення: ");
        plain=textMode?Bytes(msg.begin(),msg.end()):spaced_hex(msg);
        if(plain.size()>1024) throw std::runtime_error("Для наочної демонстрації максимум 1024 байти");
        if(textMode) {
            auto original=plain.size(); plain=pad_text(plain,bits/8);
            std::cout<<"Текст у UTF-8: "<<original<<" байт. Додано "<<plain.size()-original<<" байт PKCS#7.\nЦе явне доповнення текстового інтерфейсу до застосування CCM.\n";
        } else if(plain.size()%(bits/8)) throw std::runtime_error("HEX-повідомлення має складатися з цілих блоків");
        aad=spaced_hex(ask("AAD у HEX [Enter = відсутні]: "));
        if(aad.size()>1024||(aad.size()>bits/8-4&&aad.size()%(bits/8))) throw std::runtime_error("AAD: до block_bytes-4 байтів або цілі блоки, максимум 1024 байти");
    }
    auto detail=ccm_only?std::string("1"):ask("Показ: 0 — результат, 1 — етапи CCM, 2 — Калина та CCM [Enter = 2]: ");
    if(detail.empty()) detail="2";
    if(detail!="0"&&detail!="1"&&detail!="2") throw std::runtime_error("Виберіть 0, 1 або 2");
    bool pause=detail!="0"&&ask("Зупинятися після кожного кроку? 1 — так [Enter = весь процес одразу]: ")=="1";
    std::cout<<"\nКлюч: "<<hex(key)<<"\nNonce: "<<hex(nonce)<<"\nAAD: "<<hex(aad)<<"\nПовідомлення для CCM: "<<hex(plain)<<"\nТег: 16 байт. Nb: 4.\n";
    if(detail!="0") algorithm_map();
    if(detail=="2"&&!plain.empty()) {
        std::cout<<"\nРОЗБІР КАЛИНИ: окремо шифруємо перший блок повідомлення.\nЦе ілюстрація базового E(K, блок), а не блок шифртексту CCM.\n";
        Kalyna k(bits,key); Bytes first(plain.begin(),plain.begin()+bits/8); auto explained=k.explain(first,display_steps(true,pause));
        if(explained!=k.encrypt(first)) throw std::runtime_error("Покрокове перетворення не збіглося з еталоном");
        std::cout<<"Результат покрокового перетворення збігся з KalynaEncipher.\n";
    }
    Kccm c(bits,key,16); if(detail!="0") c.set_trace(display_steps(false,pause));
    auto packet=c.seal(nonce,aad,plain); c.set_trace({}); auto recovered=c.open(nonce,aad,packet);
    if(textMode) recovered=unpad_text(recovered,bits/8);
    std::cout<<"\nРЕЗУЛЬТАТ\nШифртекст: "<<hex(Bytes(packet.begin(),packet.end()-16))<<"\nТег: "<<hex(Bytes(packet.end()-16,packet.end()))<<"\nПакет: "<<hex(packet)<<"\nПеревірка тега: УСПІШНО\nВідновлено (HEX): "<<hex(recovered)<<"\n";
    if(textMode) std::cout<<"Відновлений текст: "<<std::string(recovered.begin(),recovered.end())<<"\n";
    std::cout<<"\nПеревірка захисту: навмисно змінюємо один біт пакета; очікуємо відмову.\n";
    packet[0]^=1; try {c.open(nonce,aad,packet); throw std::logic_error("Підміну не виявлено");} catch(const std::runtime_error& e) {std::cout<<"Підміну виявлено, текст не видано: "<<e.what()<<"\n";}
}
