#ifndef _CASERV_MODELS_STATUS_RESPONSE_H_
#define _CASERV_MODELS_STATUS_RESPONSE_H_

#include <string>

#include <oatpp/macro/codegen.hpp>
#include <oatpp/Types.hpp>

#include OATPP_CODEGEN_BEGIN(DTO)

namespace caserv
{
	namespace models
	{
		class status_response : public oatpp::DTO
		{
			DTO_INIT(status_response, DTO)

			DTO_FIELD_INFO(status)
			{
				info->description = "status code description";
			}
			DTO_FIELD(String, status);

			DTO_FIELD_INFO(code)
			{
				info->description = "status code";
			}
			DTO_FIELD(Int32, code);

			DTO_FIELD_INFO(message)
			{
				info->description = "verbose message";
			}
			DTO_FIELD(String, message);
		};
	} // namespace models
} // namespace caserv

#endif // !_CASERV_MODELS_STATUS_RESPONSE_H_
