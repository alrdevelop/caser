#ifndef _CASERV_COMMON_DATETIME_H_
#define _CASERV_COMMON_DATETIME_H_

#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>

namespace datetime {

using DateTime = std::time_t;
using DateTimePtr = std::shared_ptr<DateTime>;

inline std::string utc_now_str() {
  auto t = std::chrono::system_clock::now();
  return std::format("{:%Y-%m-%d %H:%M:%S %Z}", t);
}

inline time_t utc_now() {
  auto t = std::chrono::system_clock::now();
  return std::chrono::system_clock::to_time_t(t);
}

inline time_t from_utcstring(const std::string &dateTime) {
  struct std::tm tm;
  std::istringstream ss(dateTime);
  ss >> std::get_time(&tm, ":%Y-%m-%d %H:%M:%S %Z");
  return mktime(&tm);
}

inline const std::string& to_utcstring(const DateTime& dt){
  struct std::tm tm;
  return std::put_time(std::gmtime(&dt),":%Y-%m-%d %H:%M:%S %Z");
}


} // namespace datetime

#endif //_CASERV_COMMON_DATETIME_H_