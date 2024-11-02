#ifndef _CASERV_CONTRACTS_CERTIFICATE_H_
#define _CASERV_CONTRACTS_CERTIFICATE_H_

#include "./../common/datetime.h"
#include "certificate_request.h"
#include "paged_response.h"
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace contracts {

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

// TODO: separate db models and service requests/responses
struct CreateCertificateAuthorityModel {
  JuridicalPersonCertificateRequest request;
  std::string_view publicUrl;
};
struct StoredCertificateAuthorityModel {
  std::string_view serial;
  std::string_view thumbprint;
  std::string_view commonName;
  DateTimePtr issueDate;
  std::string_view publicUrl;
};

using CreateCertificateAuthorityModelPtr =
    std::shared_ptr<CreateCertificateAuthorityModel>;
using StoredCertificateAuthorityModelPtr =
    std::shared_ptr<StoredCertificateAuthorityModel>;
} // namespace contracts

#endif //_CASERV_CONTRACTS_CERTIFICATE_H_