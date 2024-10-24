#include "pgdatabase.h"
#include "./../common/logger.h"
#include <cstdint>
#include <memory>
#include <openssl/rsa.h>
#include <pqxx/internal/statement_parameters.hxx>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace postrgre;

PgDatabase::PgDatabase(const std::string_view &connectionString)
    : _connectionString(connectionString) {}

PgDatabase::~PgDatabase() {}

// bool PgDatabase::Init() {
//   LOG_INFO("Initialize PgDatabase...");
//   auto connectionString = _settings->GetParam("PgDatabse", "");
//   return Init(connectionString);
// }

// bool PgDatabase::Init(const std::string_view& connectionString) {
//   if (connectionString.empty())
//     throw std::runtime_error("PgDatabse connection string not set");
//   _conn = new pqxx::connection(connectionString);
//   LOG_INFO("Checking database struct.");
//   // TODO: create or update database
//   pqxx::work migration(*_conn);
//   auto query = "SELECT 1;";
//   pqxx::result result = migration.exec(query);
//   if (result.size() == 1) {
//     LOG_INFO("ddd");
//   }
//   LOG_INFO("Initalize PgDatabase success.");
// }

CertificateModelPtr PgDatabase::GetCertificate(const std::string &certSerial) {
  pqxx::connection conn(_connectionString.data());
  static auto query =
      "SELECT \"serial\", \"thumbprint\", \"caSerial\", \"commonName\", \"issueDate\", \"revoked\", \"revokeDate\" " 
      "FROM certificates " 
      "WHERE \"serial\" = $1 "
      "ORDER BY \"issueDate\" LIMIT 1";
  pqxx::work tran(conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revoked,
             revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, bool, std::string_view>(
           query, {certSerial})) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revoked = revoked;
    model->revokeDate = revokeDate;
    return model;
  }
  tran.commit();
  return nullptr;
}

std::vector<CertificateModelPtr>
PgDatabase::GetCertificates(const std::string &caSerial) {
  pqxx::connection conn(_connectionString.data());
  std::vector<CertificateModelPtr> result;
  static auto query =
      "SELECT \"serial\", \"thumbprint\", \"caSerial\", \"commonName\", \"issueDate\", \"revoked\", \"revokeDate\" " 
      "FROM certificates " 
      "WHERE \"caSerial\" = $1";
  pqxx::work tran(conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revoked,
             revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, bool, std::string_view>(
           query, {caSerial})) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revoked = revoked;
    model->revokeDate = revokeDate;
    result.push_back(model);
  }
  tran.commit();
  return result;
}

std::vector<CertificateModelPtr>
PgDatabase::GetAllCertificates() {
  pqxx::connection conn(_connectionString.data());
  std::vector<CertificateModelPtr> result;
  static auto query =
      "SELECT \"serial\", \"thumbprint\", \"caSerial\", \"commonName\", \"issueDate\", \"revoked\", \"revokeDate\" " 
      "FROM certificates";
  pqxx::work tran(conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revoked,
             revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, bool, std::string_view>(
           query)) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revoked = revoked;
    model->revokeDate = revokeDate;
    result.push_back(model);
  }
  tran.commit();
  return result;
}

std::vector<CertificateModelPtr>
PgDatabase::GetRevokedList(const std::string &caSerial) {
  pqxx::connection conn(_connectionString.data());
  std::vector<CertificateModelPtr> result;
  static auto query =
      "SELECT \"serial\", \"thumbprint\", \"caSerial\", \"commonName\", \"issueDate\", \"revoked\", \"revokeDate\" " 
      "FROM certificates " 
      "WHERE \"revoked\" = true AND \"caSerial\" = $1";
  pqxx::work tran(conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revoked,
             revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, bool, std::string_view>(
           query, {caSerial})) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revoked = revoked;
    model->revokeDate = revokeDate;
    result.push_back(model);
  }
  tran.commit();
  return result;
}

CertificateAuthorityModelPtr PgDatabase::GetCa(const std::string &serial) {
  pqxx::connection conn(_connectionString.data());
  static auto query =
      "SELECT \"serial\", \"thumbprint\", \"commonName\", \"issueDate\", \"certificate\", \"privateKey\" " 
      "FROM ca " 
      "WHERE \"serial\" = $1 "
      "ORDER BY \"issueDate\" LIMIT 1";
  pqxx::work tran(conn);

  for (auto [serial, thumbprint, commonName, issueDate, certificate,
             privateKey] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, std::string_view>(
           query, {serial})) {
    auto model = std::make_shared<CertificateAuthorityModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->certificate = std::vector<uint8_t>(certificate.begin(), certificate.end());
    model->privateKey = std::vector<uint8_t>(privateKey.begin(), privateKey.end());
    return model;
  }
  tran.commit();
  return nullptr;
}

std::vector<CertificateAuthorityModelPtr>
PgDatabase::GetAllCa() {
  pqxx::connection conn(_connectionString.data());
  std::vector<CertificateAuthorityModelPtr> result;
  static auto query =
      "SELECT \"serial\", \"thumbprint\", \"commonName\", \"issueDate\", \"certificate\", \"privateKey\" " 
      "FROM ca";
  pqxx::work tran(conn);

  for (auto [serial, thumbprint, commonName, issueDate, certificate,
             privateKey] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, std::string_view>(
           query)) {
    auto model = std::make_shared<CertificateAuthorityModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->certificate = std::vector<uint8_t>(certificate.begin(), certificate.end());
    model->privateKey = std::vector<uint8_t>(privateKey.begin(), privateKey.end());
    result.push_back(model);
  }
  tran.commit();
  return result;
}

void PgDatabase::AddCertificate(const CertificateModel &cert) {}

void PgDatabase::AddCA(const CertificateAuthorityModel &ca) {
  pqxx::connection conn(_connectionString.data());
  static auto query =
      "INSERT INTO ca(\"serial\", \"thumbprint\", \"commonName\", \"certificate\", \"privateKey\", \"publicUrl\" ) "
      "VALUES ($1, $2, $3, $4, $5, $6)";
  conn.prepare("insert_ca", query);
  pqxx::work tran(conn);
  pqxx::binarystring certBlob(ca.certificate.data(), ca.certificate.size());
  pqxx::binarystring pkBlob(ca.privateKey.data(), ca.privateKey.size());
  auto result = tran.exec_prepared("insert_ca", ca.serial, ca.thumbprint, ca.commonName, certBlob, pkBlob, ca.publicUrl );
  tran.commit();
}

void PgDatabase::MakeCertificateRevoked(const std::string &serial,
                                        const std::string &revokeDate) {}
