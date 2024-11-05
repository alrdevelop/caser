#ifndef _CASERV_HTTP_POST_CREATE_CA_H_
#define _CASERV_HTTP_POST_CREATE_CA_H_

#include "./../service/caservice.h"
#include "base/post_endpoint.h"

#include <httpserver.hpp>
#include <microhttpd.h>

namespace http {

using namespace nlohmann;
using namespace nlohmann::literals;

class CreateCaEndpoint
    : public ApiPostEndpoint<service::models::CreateCertificateAuthorityModel> {
public:
  CreateCaEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~CreateCaEndpoint() = default;
  const char *Route() const override { return "ca/create/"; }

protected:
  service::models::CreateCertificateAuthorityModel
  BuildRequestModel(const httpserver::http_request &req) override {
    json jObj = json::parse(req.get_content());
    auto issueReq = jObj.template get<service::models::CreateCertificateAuthorityModel>();
    return issueReq;
  }

  HttpResponsePtr Handle(const service::models::CreateCertificateAuthorityModel &args) override {
    auto result = _caService->CreateCA(args);

    if (result == nullptr)
      return HttpResponsePtr(new httpserver::string_response("", 404));
    json response = result;

    return HttpResponsePtr(
        new httpserver::string_response(response.dump(), 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace http


#endif //_CASERV_HTTP_POST_CREATE_CA_H_