#ifndef _CASERV_HTTP_ISSUE_CERTIFICATE_H_
#define _CASERV_HTTP_ISSUE_CERTIFICATE_H_

#include "./../service/caservice.h"
#include "base/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>
#include <utility>

namespace http {

using namespace nlohmann;
using namespace nlohmann::literals;

class IssuePhysicalPersonEndpoint
    : public ApiGetEndpoint<std::pair<std::string_view, base::PhysicalPersonCertificateRequest>> {
public:
  IssuePhysicalPersonEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~IssuePhysicalPersonEndpoint() = default;
  const char *Route() const override { return "ca/{caSerial}/issue/pp"; }

protected:
  std::pair<std::string_view, base::PhysicalPersonCertificateRequest>
  BuildRequestModel(const httpserver::http_request &req) override {
    auto pathPieces = req.get_path_pieces();
    auto args = req.get_arg("caSerial").get_all_values();
    if (args.empty())
      throw std::runtime_error("Invalid request");
    return std::make_pair(args[0], base::PhysicalPersonCertificateRequest());
  }

  HttpResponsePtr Handle(
      const std::pair<std::string_view, base::PhysicalPersonCertificateRequest>
          &args) override {
    auto cont = _caService->CreateClientCertificate(args.first, args.second);

    if (cont == nullptr)
      return HttpResponsePtr(new httpserver::string_response("", 404));
    return HttpResponsePtr(new web::FileResponse(con, 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace http

#endif //_CASERV_HTTP_ISSUE_CERTIFICATE_H_