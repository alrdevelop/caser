#ifndef _CASERV_HTTPSERVICE_GET_CERTIFICATES_H_
#define _CASERV_HTTPSERVICE_GET_CERTIFICATES_H_

#include "./../service/caservice.h"
#include "./../web/get_endpoint.h"
#include "./../json/type_spec/certificate_model_spec.h"

#include <httpserver.hpp>
#include <string_view>

namespace httpservice {

using namespace nlohmann;
using namespace nlohmann::literals;

class GetCertificatesEndpoint : public web::ApiGetEndpoint<std::string_view> {
public:
  GetCertificatesEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~GetCertificatesEndpoint() = default;
  const char *Route() const override { return "ca/{caSerial}/certificates"; }

protected:
  std::string_view
  BuildRequestModel(const httpserver::http_request &req) override {
    auto pathPieces = req.get_path_pieces();
    auto args = req.get_arg("caSerial").get_all_values();
    if (args.empty())
      throw std::runtime_error("Invalid request");
    return args[0];
  }

  HttpResponsePtr Handle(const std::string_view &caSerial) override {
    auto certs = _caService->GetCertificates(caSerial.data());
    json response = certs;

    return HttpResponsePtr(
        new httpserver::string_response(response.dump(), 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace httpservice

#endif //_CASERV_HTTPSERVICE_GET_CERTIFICATES_H_
