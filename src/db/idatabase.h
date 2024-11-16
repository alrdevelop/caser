#ifndef _CASERV_DB_IDATABASE_H_
#define _CASERV_DB_IDATABASE_H_

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "models/models.h"

namespace db {

using namespace models;

class IDataBase {
public:
  virtual ~IDataBase() = default;
  virtual void AddCertificate(const CertificateModel &cert) = 0;
  virtual CertificateModelPtr GetCertificate(const std::string &serial) = 0;
  virtual std::vector<CertificateModelPtr>
  GetCertificates(const std::string &caSerial) = 0;
  virtual std::vector<CertificateModelPtr> GetAllCertificates() = 0;

  virtual void AddCA(const CertificateAuthorityModel &ca) = 0;
  virtual CertificateAuthorityModelPtr GetCa(const std::string &serial) = 0;
  virtual std::vector<CertificateAuthorityModelPtr> GetAllCa() = 0;
  virtual std::vector<std::byte> GetCaCertificateData(const std::string &serial) = 0;

  virtual void AddCrl(const CrlModel &crl) = 0;
  virtual CrlModelPtr GetActualCrl(const std::string &caSerial) = 0;

  virtual void MakeCertificateRevoked(const std::string &serial,
                                      const DateTimePtr revokeDate) = 0;
  virtual std::vector<CertificateModelPtr>
  GetRevokedListOrderByRevokeDateDesc(const std::string &caSerial) = 0;
  virtual CertificateModelPtr GetLastRevoked(const std::string &caSerial) = 0;
};

using IDataBasePtr = std::shared_ptr<IDataBase>;

} // namespace db

#endif //_CASERV_DB_IDATABASE_H_
