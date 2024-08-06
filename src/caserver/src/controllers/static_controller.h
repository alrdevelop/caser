#ifndef _CASERV_CONTROLLERS_STATIC_CONTROLLER_H_
#define _CASERV_CONTROLLERS_STATIC_CONTROLLER_H_


#include "../defines.h"

#include <oatpp/json/ObjectMapper.hpp>
#include <oatpp/macro/codegen.hpp>
#include <oatpp/macro/component.hpp>

#include OATPP_CODEGEN_BEGIN(ApiController)

namespace caserv
{
	namespace controllers
	{
		class static_controller : public api_controller
		{
		public:
			static_controller(const std::shared_ptr<oatpp::web::mime::ContentMappers>& contentMappers) : api_controller(contentMappers){}

			static std::shared_ptr<static_controller> createShared(OATPP_COMPONENT(const std::shared_ptr<oatpp::web::mime::ContentMappers>, contentMappers))
			{
				return std::make_shared<static_controller>(contentMappers);
			}

			ENDPOINT("GET", "/", root)
			{
				static const char* html = 
					"<html lang='en'>"
					"  <head>"
					"    <meta charset=utf-8/>"
					"  </head>"
					"  <body>"
					"    <p>Hello CRUD example project!</p>"
					"    <a href='swagger/ui'>Checkout Swagger-UI page</a>"
					"  </body>"
					"</html>";

				auto response = createResponse(Status::CODE_200, html);
				response->putHeader(Header::CONTENT_TYPE, "text/html");
				return response;
			}
		};
	}
}

#endif //_CASERV_CONTROLLERS_STATIC_CONTROLLER_H_