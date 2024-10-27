#include "pgdatabase.h"
#include "./../common/logger.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <openssl/rsa.h>
#include <pqxx/internal/concat.hxx>
#include <pqxx/internal/statement_parameters.hxx>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace postgre;

PgDatabase::PgDatabase(const std::string_view &connectionString)
    : _connections(connectionString, 10) {}

PgDatabase::~PgDatabase() {}

CertificateModelPtr PgDatabase::GetCertificate(const std::string &certSerial) {
  auto conn = _connections.GetConnection();
  try {
    static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                        "\"commonName\", \"issueDate\", \"revokeDate\" "
                        "FROM certificates "
                        "WHERE \"serial\" = $1 "
                        "ORDER BY \"issueDate\" LIMIT 1";
    pqxx::work tran(*conn);

    for (auto [serial, thumbprint, caSerial, commonName, issueDate,
               revokeDate] :
         tran.query<std::string_view, std::string_view, std::string_view,
                    std::string_view, std::string_view, std::string_view>(
             query, {certSerial})) {
      auto model = std::make_shared<CertificateModel>();
      model->serial = serial;
      model->thumbprint = thumbprint;
      model->caSerial = caSerial;
      model->commonName = commonName;
      model->issueDate = issueDate;
      model->revokeDate = revokeDate;
      return model;
    }
    tran.commit();
    return nullptr;

  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

std::vector<CertificateModelPtr>
PgDatabase::GetCertificates(const std::string &caSerial) {
  auto conn = _connections.GetConnection();
  try {

  std::vector<CertificateModelPtr> result;
  static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                      "\"commonName\", \"issueDate\", \"revokeDate\" "
                      "FROM certificates "
                      "WHERE \"caSerial\" = $1";
  pqxx::work tran(*conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, std::string_view>(
           query, {caSerial})) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revokeDate = revokeDate;
    result.push_back(model);
  }
  tran.commit();
  return result;
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

std::vector<CertificateModelPtr> PgDatabase::GetAllCertificates() {

  auto conn = _connections.GetConnection();
  try {
  std::vector<CertificateModelPtr> result;
  static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                      "\"commonName\", \"issueDate\", \"revokeDate\" "
                      "FROM certificates";
  pqxx::work tran(*conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, std::string_view>(
           query)) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revokeDate = revokeDate;
    result.push_back(model);
  }
  tran.commit();
  return result;
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

std::vector<CertificateModelPtr>
PgDatabase::GetRevokedList(const std::string &caSerial) {

  auto conn = _connections.GetConnection();
  try {
  std::vector<CertificateModelPtr> result;
  static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                      "\"commonName\", \"issueDate\", \"revokeDate\" "
                      "FROM certificates "
                      "WHERE \"revokedDate\" IS NOT NULL AND \"caSerial\" = $1";
  pqxx::work tran(*conn);

  for (auto [serial, thumbprint, caSerial, commonName, issueDate, revokeDate] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, std::string_view, std::string_view>(
           query, {caSerial})) {
    auto model = std::make_shared<CertificateModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->caSerial = caSerial;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->revokeDate = revokeDate;
    result.push_back(model);
  }
  tran.commit();
  return result;
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

CertificateAuthorityModelPtr PgDatabase::GetCa(const std::string &serial) {

  auto conn = _connections.GetConnection();
  try {
  static auto query = "SELECT \"serial\", \"thumbprint\", \"commonName\", "
                      "\"issueDate\", \"certificate\", \"privateKey\" "
                      "FROM ca "
                      "WHERE \"serial\" = $1 "
                      "ORDER BY \"issueDate\" LIMIT 1";
  pqxx::work tran(*conn);

  for (auto [serial, thumbprint, commonName, issueDate, certificate,
             privateKey] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, pqxx::bytes, pqxx::bytes>(query,
                                                              {serial})) {
    auto model = std::make_shared<CertificateAuthorityModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->certificate =
        std::vector<std::byte>(certificate.begin(), certificate.end());
    model->privateKey =
        std::vector<std::byte>(privateKey.begin(), privateKey.end());
    return model;
  }
  tran.commit();
  return nullptr;
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

std::vector<CertificateAuthorityModelPtr> PgDatabase::GetAllCa() {

  auto conn = _connections.GetConnection();
  try {
  std::vector<CertificateAuthorityModelPtr> result;
  static auto query = "SELECT \"serial\", \"thumbprint\", \"commonName\", "
                      "\"issueDate\", \"certificate\", \"privateKey\" "
                      "FROM ca";
  pqxx::work tran(*conn);

  for (auto [serial, thumbprint, commonName, issueDate, certificate,
             privateKey] :
       tran.query<std::string_view, std::string_view, std::string_view,
                  std::string_view, pqxx::bytes, pqxx::bytes>(query)) {
    auto model = std::make_shared<CertificateAuthorityModel>();
    model->serial = serial;
    model->thumbprint = thumbprint;
    model->commonName = commonName;
    model->issueDate = issueDate;
    model->certificate =
        std::vector<std::byte>(certificate.begin(), certificate.end());
    model->privateKey =
        std::vector<std::byte>(privateKey.begin(), privateKey.end());
    result.push_back(model);
  }
  tran.commit();
  return result;
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

void PgDatabase::AddCertificate(const CertificateModel &cert) {

  auto conn = _connections.GetConnection();
  try {
  static auto query =
      "INSERT INTO certificates(\"serial\", \"thumbprint\", \"caSerial\", "
      "\"commonName\", \"issueDate\", \"revokeDate\") "
      "VALUES ($1, $2, $3, $4, $5, $6)";
  conn->prepare("insert_cert", query);
  pqxx::work tran(*conn);
  auto result = tran.exec_prepared("insert_cert", cert.serial, cert.thumbprint,
                                   cert.caSerial, cert.commonName,
                                   cert.issueDate, nullptr);
  tran.commit();
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

void PgDatabase::AddCA(const CertificateAuthorityModel &ca) {

  auto conn = _connections.GetConnection();
  try {
  static auto query =
      "INSERT INTO ca(\"serial\", \"thumbprint\", \"commonName\", "
      "\"issueDate\", \"certificate\", \"privateKey\", \"publicUrl\" ) "
      "VALUES ($1, $2, $3, $4, $5, $6, $7)";
  conn->prepare("insert_ca", query);
  pqxx::work tran(*conn);
  auto result = tran.exec_prepared(
      "insert_ca", ca.serial, ca.thumbprint, ca.commonName, ca.issueDate,
      pqxx::binary_cast(ca.certificate.data(), ca.certificate.size()),
      pqxx::binary_cast(ca.privateKey.data(), ca.privateKey.size()),
      ca.publicUrl);
  tran.commit();
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}

void PgDatabase::MakeCertificateRevoked(const std::string &serial,
                                        const std::string &revokeDate) {

  auto conn = _connections.GetConnection();
  try {

  static auto query = "UPDATE certificates SET \"revokeDate\" = $1"
                      "WHERE serial = $2";
  conn->prepare("revoke_cert", query);
  pqxx::work tran(*conn);
  auto result = tran.exec_prepared("revoke_cert", serial, revokeDate);
  tran.commit();
  } catch (...) {
    _connections.FreeConnection(conn);
    throw;
  }
}
