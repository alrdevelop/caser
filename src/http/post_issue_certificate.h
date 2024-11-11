#ifndef _CASERV_HTTP_ISSUE_CERTIFICATE_H_
#define _CASERV_HTTP_ISSUE_CERTIFICATE_H_

#include "./../service/caservice.h"
#include "base/post_endpoint.h"

#include <httpserver.hpp>
#include <string_view>
#include <utility>
#include <microhttpd.h>
#include "base/file_response.h"

namespace http {

using namespace nlohmann;
using namespace nlohmann::literals;

class IssueCertificateEndpoint
    : public ApiPostEndpoint<std::pair<std::string_view, service::models::IssueCertificateModel>> {
public:
  IssueCertificateEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~IssueCertificateEndpoint() = default;
  const char *Route() const override { return "ca/{caSerial}/issue/"; }

protected:
  std::pair<std::string_view, service::models::IssueCertificateModel>
  BuildRequestModel(const httpserver::http_request &req) override {
    auto pathPieces = req.get_path_pieces();
    auto args = req.get_arg("caSerial").get_all_values();
    if (args.empty())
      throw std::runtime_error("Invalid request");
    json jObj = json::parse(req.get_content());
    auto issueReq = jObj.template get<service::models::IssueCertificateModel>();
    return std::make_pair(args[0], issueReq);
  }

  HttpResponsePtr Handle(
      const std::pair<std::string_view, service::models::IssueCertificateModel>
          &args) override {
    auto result = _caService->CreateClientCertificate(args.first, args.second);

    if (result == nullptr)
      return HttpResponsePtr(new httpserver::string_response("", 404));
    return HttpResponsePtr(new FileResponse(std::format("{}.pfx", result->serialNumber), result->container, 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace http

#endif //_CASERV_HTTP_ISSUE_CERTIFICATE_H_