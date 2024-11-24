#ifndef _CASERV_HTTP_BASE_GET_ENDPOINT_H_
#define _CASERV_HTTP_BASE_GET_ENDPOINT_H_

#include "endpoint.h"
#include <exception>
#include <httpserver.hpp>

#include "./../../common/logger.h"
#include "validation_error.h"

namespace http {

template <typename TRequest>
class ApiGetEndpoint : public ApiEndpoint<TRequest> {
public:
  HttpResponsePtr render_GET(const httpserver::http_request &req) {
    try {
      auto model = this->BuildRequestModel(req);
      return this->Handle(model);
    } catch (const ValidationError &ex) {
      LOG_ERROR("Validation error: {}", ex.what());
      return HttpResponsePtr(new httpserver::string_response(ex.what(), 500));
    } catch (const std::exception &ex) {
      LOG_ERROR("Error: {}", ex.what());
      return HttpResponsePtr(new httpserver::string_response("", 500));
    } catch (...) {
      LOG_ERROR("Unhandled exception");
      return HttpResponsePtr(new httpserver::string_response("", 500));
    }
  }
};

} // namespace http

#endif //_CASERV_HTTP_BASE_GET_ENDPOINT_H_