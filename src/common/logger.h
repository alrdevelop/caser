#ifndef _CASERV_COMMON_LOGGER_H_
#define _CASERV_COMMON_LOGGER_H_

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#define LOGGER_FORMAT "[%^%l%$] %v"
#define PROJECT_NAME "caserv"

// Mainly for IDEs
#ifndef ROOT_PATH_SIZE
#	define ROOT_PATH_SIZE 0
#endif

#define __FILENAME__ (static_cast<const char *>(__FILE__) + ROOT_PATH_SIZE)

#define LOG_INFO(...) spdlog::info(__VA_ARGS__);
#define LOG_WARNING(...) spdlog::warn(__VA_ARGS__);
#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__);

#if !defined(NDEBUG) || defined(DEBUG) || defined(_DEBUG)
#	define LOG_ERROR(...) spdlog::error("[{}:{}] {}", __FILENAME__, __LINE__, fmt::format(__VA_ARGS__));
#else
#	define LOG_ERROR(...) spdlog::error(__VA_ARGS__);
#endif

#endif //_CASERV_COMMON_LOGGER_H_