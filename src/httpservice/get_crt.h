#ifndef _CASERV_HTTPSERVICE_GET_CRT_H_
#define _CASERV_HTTPSERVICE_GET_CRT_H_

#include "./../service/caservice.h"
#include "./../web/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>

namespace httpservice {

class GetCrtEndpoint : public web::ApiGetEndpoint<std::string_view> {
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

} // namespace httpservice

#endif //_CASERV_HTTPSERVICE_GET_CRT_H_