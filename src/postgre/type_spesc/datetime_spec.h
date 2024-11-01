#ifndef _CASERV_POSTGRE_TYPE_DATETIME_H_
#define _CASERV_POSTGRE_TYPE_DATETIME_H_

#include <pqxx/pqxx>
#include "./../../common/datetime.h"

namespace pqxx {
template <> std::string const type_name<datetime::DateTimePtr>{"DateTimePtr"};
template <> struct nullness<datetime::DateTimePtr> {
  static constexpr bool has_null{true};
  static constexpr bool always_null{false};

  static bool is_null(datetime::DateTimePtr const &value) {
    return value == nullptr;
  }

  [[nodiscard]] static datetime::DateTimePtr null() { return nullptr; }
};

template <> struct string_traits<datetime::DateTimePtr> {
  static constexpr bool converts_to_string{true};
  static constexpr bool converts_from_string{true};

  static zview to_buf(char *begin, char *end, datetime::DateTimePtr const &value) {
    return datetime::to_utcstring(value);
  }

  static char *into_buf(char *begin, char *end, datetime::DateTimePtr const &value) {
    if(value == nullptr) return nullptr;
    auto dt = datetime::to_utcstring(value);
    memccpy(begin, dt.c_str(), '\0', dt.length());
    return begin + dt.length();
  }
  
  //2012-08-24 14:00:00+03:00
  static std::size_t size_buffer(datetime::DateTimePtr const &value) noexcept { return 33; }

  static datetime::DateTimePtr from_string(std::string_view text) {
    if(text.empty()) return nullptr;
    return datetime::from_utcstring(text.data());
  }
};
} // namespace pqxx


#endif //_CASERV_POSTGRE_TYPE_DATETIME_H_