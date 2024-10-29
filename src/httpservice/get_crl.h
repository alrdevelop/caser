#ifndef _CASERV_HTTPSERVICE_GET_CRL_H_
#define _CASERV_HTTPSERVICE_GET_CRL_H_

#include "./../service/caservice.h"
#include "./../web/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>

namespace httpservice {

class GetCrlEndpoint : public web::ApiGetEndpoint<std::string_view> {
public:
  GetCrlEndpoint(serivce::CaServicePtr caService);
  virtual ~GetCrlEndpoint();

protected:
  std::string_view BuildRequestModel(const httpserver::http_request &req);
  HttpResponsePtr Handle(const std::string_view &request);

private:
  serivce::CaServicePtr _caService;
};

} // namespace httpservice

#endif //_CASERV_HTTPSERVICE_GET_CRL_H_