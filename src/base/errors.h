#ifndef _CASERV_BASE_ERRORS_H_
#define _CASERV_BASE_ERRORS_H_

#include <stdexcept>
#include <string>

namespace base {

namespace errors {

class CryptoProviderError : public std::runtime_error {
public:
  CryptoProviderError(const std::string &msg) : std::runtime_error(msg) {
    _message = std::string(std::runtime_error::what());
  }
  const char *what() const noexcept override {
    return  _message.c_str();
  }
private:
  std::string _message;
};

} // namespace error
} // namespace base

#endif //_CASERV_BASE_ERRORS_H_