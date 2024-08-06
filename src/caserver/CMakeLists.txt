# CMakeList.txt : CMake project for caserver, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("caserver")

# Deps
find_package(oatpp CONFIG REQUIRED)
find_package(oatpp-swagger CONFIG REQUIRED)


# Add source to this project's executable.
add_executable (caserver 
	"src/caserver.cpp" 
	"src/caserver.h"
	"src/defines.h"
	"src/models/status_response.h"
	"src/handlers/error_handler.cpp"
	"src/handlers/error_handler.h"
 "src/controllers/static_controller.h" "src/components/swagger.h" "src/components/app.h")

target_link_libraries(caserver PRIVATE oatpp::oatpp oatpp::oatpp-swagger)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET caserver PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
