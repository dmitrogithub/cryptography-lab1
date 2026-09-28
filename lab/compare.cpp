#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include "../ciphers-speed/time_measure.hpp"
#include "../ciphers-speed/Kalyna/k2_128_128.hpp"
#include "../ciphers-speed/Kalyna/k2_128_256.hpp"
#include "../ciphers-speed/Kalyna/k2_256_256.hpp"
#include "../ciphers-speed/Kalyna/k2_256_512.hpp"
#include "../ciphers-speed/Kalyna/k2_512_512.hpp"
#include "../ciphers-speed/aes/aes.hpp"
extern ENCRYPTED_MEMORY encrypted_memory;
void run_speed_comparison(bool csv) {
    struct Case {const char* name; void (*run)();};
    const Case cases[]={
        {"Kalyna-128/128",Test_K2_128_128_Speed_Expanded_Memory},
        {"Kalyna-128/256",Test_K2_128_256_Speed_Expanded_Memory},
        {"Kalyna-256/256",Test_K2_256_256_Speed_Expanded_Memory},
        {"Kalyna-256/512",Test_K2_256_512_Speed_Expanded_Memory},
        {"Kalyna-512/512",Test_K2_512_512_Speed_Expanded_Memory},
        {"AES-128",Test_AES_128_128_Speed_Expanded_Memory},
        {"AES-256",Test_AES_128_256_Speed_Expanded_Memory}};
    if(csv) std::cout<<"algorithm,MiB_per_run,repetitions,median_seconds,median_MiB_s,median_Mbit_s,min_MiB_s,max_MiB_s,checksum\n";
    else std::cout<<"\n"<<std::left<<std::setw(22)<<"Алгоритм"<<std::right
                  <<std::setw(15)<<"МіБ/с"<<std::setw(16)<<"Мбіт/с"<<"\n";
    std::cout<<std::fixed<<std::setprecision(6);
    for(auto& c:cases) {
        InitMemoryEncryptionBlock(); c.run(); // warm-up, not timed
        std::vector<double> times; unsigned long long checksum=0;
        for(int repeat=0;repeat<5;++repeat) {
            InitMemoryEncryptionBlock(); auto start=std::chrono::steady_clock::now(); c.run();
            times.push_back(std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count());
            checksum^=encrypted_memory.block64[repeat];
        }
        std::sort(times.begin(),times.end()); double amount=memory_amount_for_encryption*number_of_reencryptions_in_memory;
        if(csv) std::cout<<c.name<<","<<amount<<",5,"<<times[2]<<","<<amount/times[2]<<","<<amount*1048576*8/times[2]/1e6<<","<<amount/times.back()<<","<<amount/times.front()<<","<<checksum<<"\n"<<std::flush;
        else std::cout<<std::left<<std::setw(22)<<c.name<<std::right<<std::setw(15)<<std::setprecision(2)<<amount/times[2]
                      <<std::setw(16)<<amount*1048576*8/times[2]/1e6<<"\n"<<std::setprecision(6)<<std::flush;
    }
}
#ifndef KALYNA_EMBED_COMPARE
int main() {run_speed_comparison(true);}
#endif
