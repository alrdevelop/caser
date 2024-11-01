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

inline DateTimePtr utc_now() {
  auto t = std::chrono::system_clock::now();
  auto dt = new DateTime();
  *dt = std::chrono::system_clock::to_time_t(t);
  return DateTimePtr(dt);
  //return std::chrono::system_clock::to_time_t(t);
}

inline DateTimePtr from_utcstring(const std::string &dateTime) {
  struct std::tm tm;
  std::istringstream ss(dateTime);
  ss >> std::get_time(&tm, ":%Y-%m-%d %H:%M:%S %Z");
  auto dt = new DateTime();
  *dt = mktime(&tm);
  return DateTimePtr(dt);
}

inline std::string to_utcstring(const DateTime& dt){
  auto t = std::chrono::system_clock::from_time_t(dt);
  return std::format("{:%Y-%m-%d %H:%M:%S %Z}", t);
}

inline std::string to_utcstring(const DateTimePtr& dt){
  auto t = std::chrono::system_clock::from_time_t(*dt);
  return std::format("{:%Y-%m-%d %H:%M:%S %Z}", t);
}


} // namespace datetime

#endif //_CASERV_COMMON_DATETIME_H_