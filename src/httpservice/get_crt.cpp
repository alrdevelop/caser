#include "get_crt.h"
#include "./../web/file_response.h"
#include <filesystem>
#include <httpserver.hpp>
#include <microhttpd.h>
#include <stdexcept>
#include <string_view>


using namespace httpservice;

GetCrtEndpoint::GetCrtEndpoint(serivce::CaServicePtr caService) : _caService(caService) {}

GetCrtEndpoint::~GetCrtEndpoint(){}

std::string_view GetCrtEndpoint::BuildRequestModel(const httpserver::http_request &req) {
    auto pathPieces = req.get_path_pieces();
    auto args = req.get_arg("crtFile").get_all_values();
    if(args.empty()) throw std::runtime_error("Invalid request");
    return args[0];
}

HttpResponsePtr GetCrtEndpoint::Handle(const std::string_view &crtFileName) {
    auto caSerial = std::filesystem::path(crtFileName).stem();
    auto crt = _caService->GetCaCertificateData(caSerial);
    if(crt.empty()) return HttpResponsePtr(new httpserver::string_response("", 404));
    return HttpResponsePtr(new web::FileResponse(crt, 200));
}
