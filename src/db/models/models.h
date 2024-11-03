#ifndef _CASERV_DB_MODELS_H_
#define _CASERV_DB_MODELS_H_

#include "./../../common/datetime.h"
#include "./../../common/paged_response.h"
#include <cstddef>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace db {
namespace models {
using namespace datetime;

struct CertificateModel {
  std::string serial;
  std::string thumbprint;
  std::string caSerial;
  std::string commonName;
  DateTimePtr issueDate;
  DateTimePtr revokeDate;
};

struct CertificateAuthorityModel {
  std::string serial;
  std::string thumbprint;
  std::string commonName;
  DateTimePtr issueDate;
  std::vector<std::byte> certificate;
  std::vector<std::byte> privateKey;
  std::string publicUrl;
};

struct CrlModel {
  std::string caSerial;
  long number;
  DateTimePtr issueDate;
  std::string lastSerial;
  std::vector<std::byte> content;
};

using CertificateModelPtr = std::shared_ptr<CertificateModel>;
using CertificateAuthorityModelPtr = std::shared_ptr<CertificateAuthorityModel>;
using CrlModelPtr = std::shared_ptr<CrlModel>;

using CertificateModels = PagedResponse<CertificateModelPtr>;
using CertificateAuthorityModels = PagedResponse<CertificateAuthorityModelPtr>;
using CrlModels = PagedResponse<CrlModelPtr>;

} // namespace models

} // namespace db

#endif // _CASERV_DB_MODELS_H_