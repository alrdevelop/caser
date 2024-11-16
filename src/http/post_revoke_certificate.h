#ifndef _CASERV_HTTP_REVOKE_CERTIFICATE_H_
#define _CASERV_HTTP_REVOKE_CERTIFICATE_H_

#include "./../service/caservice.h"
#include "base/post_endpoint.h"

#include "base/file_response.h"
#include <httpserver.hpp>
#include <memory>
#include <microhttpd.h>
#include <string_view>
#include <utility>

namespace http {

using namespace nlohmann;
using namespace nlohmann::literals;

class RevokeCertificateEndpoint
    : public ApiPostEndpoint<service::models::RevokeCertificateModel> {
public:
  RevokeCertificateEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~RevokeCertificateEndpoint() = default;
  const char *Route() const override { return "certificate/revoke/"; }

protected:
  service::models::RevokeCertificateModel
  BuildRequestModel(const httpserver::http_request &req) override {
    json jObj = json::parse(req.get_content());
    auto revokeReq =
        jObj.template get<service::models::RevokeCertificateModel>();
    return revokeReq;
  }

  HttpResponsePtr
  Handle(const service::models::RevokeCertificateModel &req) override {
    _caService->RevokeCertificate(req);
    return HttpResponsePtr(new httpserver::string_response("", 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace http

#endif //_CASERV_HTTP_REVOKE_CERTIFICATE_H_