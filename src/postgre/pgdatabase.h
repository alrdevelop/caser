#ifndef _CASERV_POSTGRE_PGDATABASE_H_
#define _CASERV_POSTGRE_PGDATABASE_H_

#include "./../base/idatabase.h"
#include "./../common/appsettings.h"
#include <cstring>
#include <memory>
#include <mutex>
#include <pqxx/connection>
#include <pqxx/pqxx>
#include <pqxx/zview.hxx>
#include <string>
#include <string_view>
#include <vector>

#include "connection_pool.h"
namespace postgre {

using namespace contracts;

class PgDatabase : public base::IDataBase {
public:
  PgDatabase(const std::string_view &connectionString);
  ~PgDatabase();

  CertificateModelPtr GetCertificate(const std::string &serial) override;
  std::vector<CertificateModelPtr>
  GetCertificates(const std::string &caSerial) override;
  std::vector<CertificateModelPtr> GetAllCertificates() override;
  CertificateAuthorityModelPtr GetCa(const std::string &serial) override;
  std::vector<CertificateAuthorityModelPtr> GetAllCa() override;
  std::vector<std::byte> GetCaCertificateData(const std::string &serial) override;
  void AddCertificate(const CertificateModel &cert) override;
  void AddCA(const CertificateAuthorityModel &ca) override;

  void MakeCertificateRevoked(const std::string &serial,
                              const std::string &revokeDate) override;
  std::vector<CertificateModelPtr>
  GetRevokedListOrderByRevokeDateDesc(const std::string &caSerial) override;
  CertificateModelPtr GetLastRevoked(const std::string &caSerial) override;

  void AddCrl(const CrlModel &crl) override;
  CrlModelPtr GetActualCrl(const std::string &caSerial) override;

private:
  ConnectionPoolPtr _connectionPool;
};
} // namespace postgre

#endif //_CASERV_POSTGRE_PGDATABASE_H_
