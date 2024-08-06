#include "error_handler.h"
#include "../models/status_response.h"
#include <oatpp/data/stream/BufferStream.hpp>

caserv::handlers::error_handler::error_handler(const std::shared_ptr<oatpp::web::mime::ContentMappers>& mappers) : _mappers(mappers)
{
}

std::shared_ptr<outgoing_response> caserv::handlers::error_handler::renderError(const HttpServerErrorStacktrace& stacktrace)
{
    auto status = stacktrace.status;

    if(status.description == nullptr)
    {
        status.description = "Unknown error";
    }

    auto responseDto = models::status_response::createShared();
    responseDto->code = stacktrace.status.code;
    responseDto->status = "Error";
    responseDto->message = "Description";

    std::vector<oatpp::String> accept_header;
    if(stacktrace.request)
    {
        accept_header = stacktrace.request->getHeaderValues("Accept");
    }

    auto mapper = _mappers->selectMapper(accept_header);
    if(mapper == nullptr)
    {
        mapper = _mappers->getDefaultMapper();
    }

    auto response = response_factory::createResponse(stacktrace.status, responseDto, mapper);
    for(const auto& header : stacktrace.headers.getAll())
    {
        response->putHeader(header.first.toString(), header.second.toString());
    }

    return response;
}
