#ifndef _CASERV_HTTP_BASE__FILERESPONSE_H_
#define _CASERV_HTTP_BASE__FILERESPONSE_H_

#include <cstddef>
#include <format>
#include <httpserver.hpp>
#include <microhttpd.h>
#include <string>
#include <vector>

// #include "<httpserver/http_utils.hpp>"
// #include "<httpserver/http_response.hpp>"

struct MHD_Response;

namespace http {

class FileResponse : public httpserver::http_response {
public:
  FileResponse() = default;
  explicit FileResponse(
      const std::vector<std::byte> content,
      int response_code = httpserver::http::http_utils::http_ok,
      const std::string &content_type =
          httpserver::http::http_utils::application_octet_stream)
      : http_response(response_code, content_type), _content(content) {}

  explicit FileResponse(
      const std::string &fileName,
      const std::vector<std::byte> content,
      int response_code = httpserver::http::http_utils::http_ok,
      const std::string &content_type =
          httpserver::http::http_utils::application_octet_stream)
      : http_response(response_code, content_type), _content(content), _fileName(fileName) {}

  FileResponse(const FileResponse &other) = default;
  FileResponse(FileResponse &&other) noexcept = default;

  FileResponse &operator=(const FileResponse &b) = default;
  FileResponse &operator=(FileResponse &&b) = default;

  ~FileResponse() = default;

  MHD_Response *get_raw_response() {
    if (_content.empty())
      return MHD_create_response_from_buffer(0, nullptr,
                                             MHD_RESPMEM_PERSISTENT);
    if(!_fileName.empty())
      with_header("Content-Disposition", std::format("attachment; filename=\"{}\"", _fileName));
    return MHD_create_response_from_buffer(_content.size(), _content.data(),
                                           MHD_RESPMEM_MUST_COPY);
  }

private:
  std::vector<std::byte> _content;
  std::string _fileName;
};

} // namespace http

#endif //_CASERV_HTTP_BASE__FILERESPONSE_H_