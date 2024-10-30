#ifndef _CASERV_COMMON_DATETIME_H_
#define _CASERV_COMMON_DATETIME_H_

#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <sstream>
#include <string>

namespace datetime {
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

} // namespace datetime

#endif //_CASERV_COMMON_DATETIME_H_