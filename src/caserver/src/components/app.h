#ifndef _CASERV_COMPONENTS_APP_H_
#define _CASERV_COMPONENTS_APP_H_

#include "swagger.h"

#include <oatpp/web/mime/ContentMappers.hpp>
#include <oatpp/json/ObjectMapper.hpp>
#include <oatpp/web/server/HttpConnectionHandler.hpp>
#include <oatpp/web/server/HttpRouter.hpp>
#include <oatpp/web/mime/ContentMappers.hpp>
#include <oatpp/network/tcp/server/ConnectionProvider.hpp>

#include "../handlers/error_handler.h"

namespace caserv
{
	namespace components
	{
		class application
		{
		public:
			swagger swaggerComponent;

			OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::web::mime::ContentMappers>, contentMapper)([]
				{
					auto json = std::make_shared<oatpp::json::ObjectMapper>();
					json->serializerConfig().json.useBeautifier = true;
					auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
					mappers->putMapper(json);
					return mappers;
				}());

			OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>, serverConnectionProvider)([]
				{
					return oatpp::network::tcp::server::ConnectionProvider::createShared({ "0.0.0.0", 8080, oatpp::network::Address::IP_4 });
				}());

			OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, httpRouter)([]
				{
					return oatpp::web::server::HttpRouter::createShared();
				}());

			OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ConnectionHandler>, serverConnectionHandler)([]
				{
					OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router);
					OATPP_COMPONENT(std::shared_ptr<oatpp::web::mime::ContentMappers>, contentMappers);
					auto connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);
					connectionHandler->setErrorHandler(std::make_shared<handlers::error_handler>(contentMappers));
					return connectionHandler;
				}());
		};
	}
}

#endif // !_CASERV_COMPONENTS_APP_H_
