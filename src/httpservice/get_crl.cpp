#include "get_crl.h"
#include <httpserver.hpp>
#include <string_view>

using namespace httpservice;

GetCrlEndpoint::GetCrlEndpoint(serivce::CaServicePtr caService) : _caService(caService) {}

GetCrlEndpoint::~GetCrlEndpoint(){}

std::string_view GetCrlEndpoint::BuildRequestModel(const httpserver::http_request &req) {
    auto pathPieces = req.get_path_pieces();
    return std::string_view{""};
}

HttpResponsePtr GetCrlEndpoint::Handle(const std::string_view &request) {
    return HttpResponsePtr(new httpserver::string_response("", 200));
}
