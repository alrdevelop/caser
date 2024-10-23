#ifndef _CASERV_APPSETTINGS_H_
#define _CASERV_APPSETTINGS_H_

#include <cstdlib>
#include <memory>
#include <string>

class AppSettings {
public:
  AppSettings() = default;
  ~AppSettings() = default;

  std::string GetParam(const std::string &name,
                       const std::string &defaultValue) const {
    if (const char *envp = std::getenv(name.c_str()))
      return std::string(envp);
    return defaultValue;
  }
};

using AppSettingsPtr = std::shared_ptr<AppSettings>;

#endif //_CASERV_APPSETTINGS_H_