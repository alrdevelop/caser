#ifndef _CASERV_HTTP_BASE_ENDPOINT_H_
#define _CASERV_HTTP_BASE_ENDPOINT_H_

#include <httpserver.hpp>
#include <memory>

using HttpResponsePtr = std::shared_ptr<httpserver::http_response>;

namespace http {
template <typename TRequest>
class ApiEndpoint : public httpserver::http_resource {
public:
  virtual ~ApiEndpoint() = default;
  virtual const char *Route() const = 0;

  void Register(httpserver::webserver &ws) {
    LOG_INFO("Endpoint {} added.", Route());
    ws.register_resource(Route(), this);
  }

protected:
  virtual TRequest BuildRequestModel(const httpserver::http_request &req) = 0;
  virtual HttpResponsePtr Handle(const TRequest &model) = 0;
};
} // namespace http

#endif //_CASERV_HTTP_BASE_ENDPOINT_H_