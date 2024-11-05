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

  const std::string GetParam(const std::string &name,
                       const std::string &defaultValue) const {
    if (const char *envp = std::getenv(name.c_str()))
      return envp;
    return defaultValue;
  }
};

using AppSettingsPtr = std::shared_ptr<AppSettings>;

#endif //_CASERV_APPSETTINGS_H_