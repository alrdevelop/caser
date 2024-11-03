#ifndef _CASERV_HTTP_GET_CA_H_
#define _CASERV_HTTP_GET_CA_H_

#include "./../service/caservice.h"
#include "base/get_endpoint.h"

#include <httpserver.hpp>
#include <string_view>

namespace http {

using namespace nlohmann;
using namespace nlohmann::literals;

class GetCaEndpoint : public ApiGetEndpoint<std::string_view> {
public:
  GetCaEndpoint(serivce::CaServicePtr caService)
      : _caService(caService) {}
  virtual ~GetCaEndpoint() = default;
  const char *Route() const override { return "ca/{caSerial}"; }

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
    auto ca = _caService->GetCa(caSerial.data());

    if(ca == nullptr) return HttpResponsePtr(new httpserver::string_response("", 404));

    json response = ca;
    return HttpResponsePtr(
        new httpserver::string_response(response.dump(), 200));
  }

private:
  serivce::CaServicePtr _caService;
};

} // namespace httpservice

#endif //_CASERV_HTTP_GET_CA_H_
