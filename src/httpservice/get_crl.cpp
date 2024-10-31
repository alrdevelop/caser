#include "get_crl.h"
#include "./../web/file_response.h"
#include <filesystem>
#include <httpserver.hpp>
#include <microhttpd.h>
#include <stdexcept>
#include <string_view>


using namespace httpservice;

GetCrlEndpoint::GetCrlEndpoint(serivce::CaServicePtr caService) : _caService(caService) {}

GetCrlEndpoint::~GetCrlEndpoint(){}

std::string_view GetCrlEndpoint::BuildRequestModel(const httpserver::http_request &req) {
    auto pathPieces = req.get_path_pieces();
    auto args = req.get_arg("crlFile").get_all_values();
    if(args.empty()) throw std::runtime_error("Invalid request");
    return args[0];
}

HttpResponsePtr GetCrlEndpoint::Handle(const std::string_view &crlFileName) {
    auto caSerial = std::filesystem::path(crlFileName).stem();
    auto crl = _caService->GetCrl(caSerial);
    if(crl.empty()) return HttpResponsePtr(new httpserver::string_response("", 404));
    return HttpResponsePtr(new web::FileResponse(crl, 200));
}
