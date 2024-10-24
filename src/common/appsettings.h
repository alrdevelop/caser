#ifndef _CASERV_APPSETTINGS_H_
#define _CASERV_APPSETTINGS_H_

#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

class AppSettings {
public:
  AppSettings() = default;
  ~AppSettings() = default;

  std::string_view GetParam(const std::string &name,
                       const std::string &defaultValue) const {
    if (const char *envp = std::getenv(name.c_str()))
      return std::string_view(envp);
    return defaultValue;
  }
};

using AppSettingsPtr = std::shared_ptr<AppSettings>;

#endif //_CASERV_APPSETTINGS_H_