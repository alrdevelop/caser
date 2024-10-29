#ifndef _CASERV_WEB_ENDPOINT_H_
#define _CASERV_WEB_ENDPOINT_H_

#include <httpserver.hpp>
#include <memory>

using HttpResponsePtr = std::shared_ptr<httpserver::http_response>;

namespace web {
template <typename TRequest>
class ApiEndpoint : public httpserver::http_resource {
public:
  virtual ~ApiEndpoint() = default;

protected:
  virtual TRequest BuildRequestModel(const httpserver::http_request &req) = 0;
  virtual HttpResponsePtr Handle(const TRequest &model) = 0;
};
} // namespace web

#endif //_CASERV_WEB_ENDPOINT_H_