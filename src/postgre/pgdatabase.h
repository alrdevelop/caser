#ifndef _CASERV_POSTGRE_PGDATABASE_H_
#define _CASERV_POSTGRE_PGDATABASE_H_

#include "./../common/appsettings.h"
#include "./../base/idatabase.h"
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <pqxx/pqxx>
#include <pqxx/connection>

#include "connection_pool.h"

namespace postgre {

using namespace contracts;


class PgDatabase : public base::IDataBase {
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
  ConnectionPool _connections;
};
} // namespace postgre

#endif //_CASERV_POSTGRE_PGDATABASE_H_
