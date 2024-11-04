#ifndef _CASERV_HTTP_BASE_POST_ENDPOINT_H_
#define _CASERV_HTTP_BASE_POST_ENDPOINT_H_

#include "endpoint.h"
#include <exception>
#include <httpserver.hpp>

#include "./../../common/logger.h"


namespace http {

template <typename TRequest> class ApiPostEndpoint : public ApiEndpoint<TRequest> {
public:
  HttpResponsePtr render_POST(const httpserver::http_request &req) {
    try {
      auto model = this->BuildRequestModel(req);
      return this->Handle(model);
    } catch (const std::exception& ex) {
      LOG_ERROR("{}", ex.what());
      return HttpResponsePtr(new httpserver::string_response("", 500));
    } catch (...) {
      LOG_ERROR("Unhandled exception");
      return HttpResponsePtr(new httpserver::string_response("", 500));
    }
  }
};

} // http

#endif //_CASERV_HTTP_BASE_POST_ENDPOINT_H_