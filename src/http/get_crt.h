#ifndef _CASERV_HTTP_GET_CRT_H_
#define _CASERV_HTTP_GET_CRT_H_

#include "./../service/caservice.h"
#include "base/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>

namespace http {

class GetCrtEndpoint : public ApiGetEndpoint<std::string_view> {
public:
  GetCrtEndpoint(serivce::CaServicePtr caService);
  virtual ~GetCrtEndpoint();
  const char* Route() const override { return "crt/{crtFile}";}

protected:
  std::string_view BuildRequestModel(const httpserver::http_request &req) override;
  HttpResponsePtr Handle(const std::string_view &crlFileName) override;

private:
  serivce::CaServicePtr _caService;
};

} // namespace http

#endif //_CASERV_HTTP_GET_CRT_H_