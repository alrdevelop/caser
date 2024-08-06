// caserver.cpp : Defines the entry point for the application.
//

#include "caserver.h"
#include "components/app.h"
#include "controllers/static_controller.h"

using namespace std;

void run()
{
	caserv::components::application app;

	OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router);
	oatpp::web::server::api::Endpoints endpoints;
}

int main()
{
	cout << "Hello CMake." << endl;
	return 0;
}
