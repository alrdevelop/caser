#ifndef _CASERV_HANDLERS_ERROR_HANDLER_H_
#define _CASERV_HANDLERS_ERROR_HANDLER_H_

#include "../defines.h"
#include <oatpp/web/server/handler/ErrorHandler.hpp>

namespace caserv
{
    namespace handlers
    {

        class error_handler : public oatpp::web::server::handler::DefaultErrorHandler
        {
        public:
            error_handler(const std::shared_ptr<oatpp::web::mime::ContentMappers>& mappers);
            std::shared_ptr<outgoing_response> renderError(const HttpServerErrorStacktrace& stacktrace) override;
        private:
            std::shared_ptr<oatpp::web::mime::ContentMappers> _mappers;
        };
    } // namespace handlers

} // namespace caserv

#endif //_CASERV_HANDLERS_ERROR_HANDLER_H_