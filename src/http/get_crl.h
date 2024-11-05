#ifndef _CASERV_HTTP_GET_CRL_H_
#define _CASERV_HTTP_GET_CRL_H_

#include "./../service/caservice.h"
#include "base/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>

namespace http {

class GetCrlEndpoint : public ApiGetEndpoint<std::string_view> {
public:
  GetCrlEndpoint(serivce::CaServicePtr caService);
  virtual ~GetCrlEndpoint();
  const char* Route() const override { return "crl/{crlFile}";}

protected:
  std::string_view BuildRequestModel(const httpserver::http_request &req) override;
  HttpResponsePtr Handle(const std::string_view &crlFileName) override;

private:
  serivce::CaServicePtr _caService;
};

} // namespace http

#endif //_CASERV_HTTP_GET_CRL_H_