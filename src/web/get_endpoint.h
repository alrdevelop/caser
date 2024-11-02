#ifndef _CASERV_WEB_GET_ENDPOINT_H_
#define _CASERV_WEB_GET_ENDPOINT_H_

#include "./../common/logger.h"
#include "endpoint.h"
#include <exception>
#include <httpserver.hpp>

namespace web {

template <typename TRequest> class ApiGetEndpoint : public ApiEndpoint<TRequest> {
public:
  HttpResponsePtr render_GET(const httpserver::http_request &req) {
    try {
      auto model = this->BuildRequestModel(req);
      return this->Handle(model);
    }
    catch(const std::exception &ex) {
      LOG_ERROR("Error: {}", ex.what());
      return HttpResponsePtr(new httpserver::string_response("", 500));
    } 
    catch (...) {
      LOG_ERROR("Unhandled exception");
      return HttpResponsePtr(new httpserver::string_response("", 500));
    }
  }
};

} // namespace web

#endif //_CASERV_WEB_GET_ENDPOINT_H_