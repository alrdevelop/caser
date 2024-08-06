#ifndef _CASERV_COMPONENTS_SWAGGER_H_
#define _CASERV_COMPONENTS_SWAGGER_H_

#include <oatpp-swagger/Model.hpp>
#include <oatpp-swagger/Resources.hpp>
#include <oatpp/macro/component.hpp>

namespace caserv
{
	namespace components
	{
		class swagger
		{
		public:
			OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::swagger::DocumentInfo>, swaggerDocumentInfo)([] 
			{
				oatpp::swagger::DocumentInfo::Builder builder;

				builder
					.setTitle("Swagger title")
					.addServer("http://localhost:8000", "server on localhost");

				return builder.build();
			}());
		};
	}
}

#endif // !_CASERV_COMPONENTS_SWAGGER_H_
