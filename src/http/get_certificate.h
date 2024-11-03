#ifndef _CASERV_HTTP_GET_CERTIFICATE_H_
#define _CASERV_HTTP_GET_CERTIFICATE_H_

#include "./../service/caservice.h"
#include "base/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>

namespace http {

using namespace nlohmann;
using namespace nlohmann::literals;

class GetCertificateEndpoint : public ApiGetEndpoint<std::string_view> {
public:
  GetCertificateEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~GetCertificateEndpoint() = default;
  const char *Route() const override { return "certificate/{serial}"; }

protected:
  std::string_view
  BuildRequestModel(const httpserver::http_request &req) override {
    auto pathPieces = req.get_path_pieces();
    auto args = req.get_arg("serial").get_all_values();
    if (args.empty())
      throw std::runtime_error("Invalid request");
    return args[0];
  }

  HttpResponsePtr Handle(const std::string_view &serial) override {
    auto cert = _caService->GetCertificate(serial.data());
    if (cert == nullptr)
      return HttpResponsePtr(new httpserver::string_response("", 404));
    json response = cert;

    return HttpResponsePtr(
        new httpserver::string_response(response.dump(), 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace http

#endif //_CASERV_HTTP_GET_CERTIFICATE_H_
