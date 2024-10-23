#ifndef _CASERV_POSRGRE_PGDATABASE_H_
#define _CASERV_POSRGRE_PGDATABASE_H_

#include "./../common/appsettings.h"
#include "./../contracts/certificate_model.h"
#include <string>
#include <vector>
#include <pqxx/pqxx>
#include <pqxx/connection>

namespace postrgre {
using namespace contracts;

class PgDatabase {
public:
  PgDatabase(AppSettingsPtr settings);
  ~PgDatabase();
  bool Init();
  CertificateModel& GetCertificate(const std::string &serial) const;
  CertificateAuthorityModel& GetCa(const std::string &serial) const;
  void AddCertificate(const CertificateModel &cert);
  void AddCA(const CertificateAuthorityModel &ca);
  void MakeCertificateRevoked(const std::string &serial,
                              const std::string &revokeDate);
  std::vector<CertificateModel> GetRevokedList(const std::string &caSerial);

private:
  AppSettingsPtr _settings{nullptr};
  //TODO: lazy conn
  pqxx::connection* _conn{nullptr};
};
} // namespace postrgre

#endif //_CASERV_POSRGRE_PGDATABASE_H_
