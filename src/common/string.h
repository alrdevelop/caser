#ifndef _CASERV_COMMON_STRING_H_
#define _CASERV_COMMON_STRING_H_

#include <string>
#include <sstream>
#include <iostream>

template <class T>
inline std::string to_string(const T& value)
{
    std::stringstream ss;
    ss << std::fixed << value;
    return ss.str();
}

#endif //_CASERV_COMMON_STRING_H_
