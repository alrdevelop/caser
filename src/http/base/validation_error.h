#ifndef _CASERV_HTTP_VALIDATION_ERROR_H_
#define _CASERV_HTTP_VALIDATION_ERROR_H_

#include <stdexcept>
namespace http {

class ValidationError : public std::runtime_error {
public:
  ValidationError(const std::string &msg) : std::runtime_error(msg) {
    _message = std::string(std::runtime_error::what());
  }
  const char *what() const noexcept override {
    return  _message.c_str();
  }
private:
  std::string _message;
};


}

#endif //_CASERV_HTTP_VALIDATION_ERROR_H_
