#include "pgdatabase.h"
#include "./../common/logger.h"
#include <openssl/rsa.h>
#include <pqxx/internal/statement_parameters.hxx>
#include <stdexcept>
#include <string>

using namespace postrgre;

PgDatabase::PgDatabase(AppSettingsPtr settings) : _settings(settings) {}

PgDatabase::~PgDatabase() {
  if (_conn != nullptr) {
    if (_conn->is_open())
      _conn->close();
    delete _conn;
  }
}

bool PgDatabase::Init() {
  LOG_INFO("Initialize PgDatabase...");
  auto connectionString = _settings->GetParam("PgDatabse", "");
  if (connectionString.empty())
    throw std::runtime_error("PgDatabse connection string not set");
  _conn = new pqxx::connection(connectionString);
  LOG_INFO("Checking database struct.");
  // TODO: create or update database
  pqxx::work migration(*_conn);
  auto query = "SELECT 1;";
  pqxx::result result = migration.exec(query);
  if (result.size() == 1) {
    LOG_INFO("ddd");
  }
  LOG_INFO("Initalize PgDatabase success.");
}

CertificateModel &PgDatabase::GetCertificate(const std::string &serial) const {}

CertificateAuthorityModel &PgDatabase::GetCa(const std::string &serial) const {}

void PgDatabase::AddCertificate(const CertificateModel &cert) {}

void PgDatabase::AddCA(const CertificateAuthorityModel &ca) {}

void PgDatabase::MakeCertificateRevoked(const std::string &serial,
                                        const std::string &revokeDate) {}
std::vector<CertificateModel>
PgDatabase::GetRevokedList(const std::string &caSerial) {}