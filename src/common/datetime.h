#ifndef _CASERV_COMMON_DATETIME_H_
#define _CASERV_COMMON_DATETIME_H_

#include <format>
#include <string>
#include <chrono>

inline std::string datetime_now(){
    auto t = std::chrono::utc_clock::now();
    return std::format("{:%Y-%m-%d %H:%M:%S %Z}", t); 
}

#endif //_CASERV_COMMON_DATETIME_H_