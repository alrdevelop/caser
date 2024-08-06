#ifndef _CASERV_DEFINES_H_
#define _CASERV_DEFINES_H_

#include <oatpp/web/protocol/http/outgoing/ResponseFactory.hpp>
#include <oatpp/web/mime/ContentMappers.hpp>
#include <oatpp/web/server/api/ApiController.hpp>


typedef oatpp::web::protocol::http::outgoing::Response outgoing_response;
typedef oatpp::web::protocol::http::Status status;
typedef oatpp::web::protocol::http::outgoing::ResponseFactory response_factory;            
typedef oatpp::web::server::api::ApiController api_controller;

#endif //_CASERV_DEFINES_H_