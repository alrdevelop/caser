#ifndef _CASERV_POSRGRE_PGDATABASE_H_
#define _CASERV_POSRGRE_PGDATABASE_H_

#include "./../common/appsettings.h"
#include "./../contracts/certificate_model.h"
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <pqxx/pqxx>
#include <pqxx/connection>

namespace postrgre {
using namespace contracts;

using CertificateModelPtr = std::shared_ptr<CertificateModel>;
using CertificateAuthorityModelPtr = std::shared_ptr<CertificateAuthorityModel>;

class PgDatabase {
public:
  PgDatabase(const std::string_view& connectionString);
  ~PgDatabase();

  CertificateModelPtr GetCertificate(const std::string &serial);
  std::vector<CertificateModelPtr> GetCertificates(const std::string &caSerial);
  std::vector<CertificateModelPtr> GetAllCertificates();
  CertificateAuthorityModelPtr GetCa(const std::string &serial);
  std::vector<CertificateAuthorityModelPtr> GetAllCa();
  
  void AddCertificate(const CertificateModel &cert);
  void AddCA(const CertificateAuthorityModel &ca);
  
  void MakeCertificateRevoked(const std::string &serial,
                              const std::string &revokeDate);
  std::vector<CertificateModelPtr> GetRevokedList(const std::string &caSerial);

private:
  std::string_view _connectionString;
};
} // namespace postrgre

#endif //_CASERV_POSRGRE_PGDATABASE_H_
