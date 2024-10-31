#include "pgdatabase.h"
#include "./../common/logger.h"
#include "connection_pool.h"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <openssl/rsa.h>
#include <pqxx/internal/concat.hxx>
#include <pqxx/internal/statement_parameters.hxx>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace postgre;

PgDatabase::PgDatabase(const std::string_view &connectionString) {
  _connectionPool = std::make_shared<ConnectionPool>(connectionString, 10);
}

PgDatabase::~PgDatabase() {}

CertificateModelPtr PgDatabase::GetCertificate(const std::string &certSerial) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                        "\"commonName\", \"issueDate\", \"revokeDate\" "
                        "FROM certificates "
                        "WHERE UPPER(\"serial\") = UPPER($1) "
                        "ORDER BY \"issueDate\" LIMIT 1";
    pqxx::work tran(*conn);

    std::vector<CertificateModelPtr> result;
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
      result.push_back(model);
    }
    tran.commit();
    if (result.empty())
      return nullptr;
    return result[0];

  } catch (...) {
    throw;
  }
}

std::vector<CertificateModelPtr>
PgDatabase::GetCertificates(const std::string &caSerial) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    std::vector<CertificateModelPtr> result;
    static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                        "\"commonName\", \"issueDate\", \"revokeDate\" "
                        "FROM certificates "
                        "WHERE UPPER(\"caSerial\") = UPPER($1)";
    pqxx::work tran(*conn);

    for (auto [serial, thumbprint, caSerial, commonName, issueDate,
               revokeDate] :
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
    throw;
  }
}

std::vector<CertificateModelPtr> PgDatabase::GetAllCertificates() {
  try {
    std::vector<CertificateModelPtr> result;
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query = "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
                        "\"commonName\", \"issueDate\", \"revokeDate\" "
                        "FROM certificates";
    pqxx::work tran(*conn);

    for (auto [serial, thumbprint, caSerial, commonName, issueDate,
               revokeDate] :
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
    throw;
  }
}

std::vector<CertificateModelPtr>
PgDatabase::GetRevokedListOrderByRevokeDateDesc(const std::string &caSerial) {
  try {
    std::vector<CertificateModelPtr> result;
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query =
        "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
        "\"commonName\", \"issueDate\", \"revokeDate\" "
        "FROM certificates "
        "WHERE \"revokeDate\" IS NOT NULL AND UPPER(\"caSerial\") = UPPER($1)";
    pqxx::work tran(*conn);

    for (auto [serial, thumbprint, caSerial, commonName, issueDate,
               revokeDate] :
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
    throw;
  }
}

CertificateModelPtr PgDatabase::GetLastRevoked(const std::string &caSerial){
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query =
        "SELECT \"serial\", \"thumbprint\", \"caSerial\", "
        "\"commonName\", \"issueDate\", \"revokeDate\" "
        "FROM certificates "
        "WHERE \"revokeDate\" IS NOT NULL AND UPPER(\"caSerial\") = UPPER($1) ORDER BY \"revokeDate\" DESC LIMIT 1";
    pqxx::work tran(*conn);
    std::vector<CertificateModelPtr> result;

    for (auto [serial, thumbprint, caSerial, commonName, issueDate,
               revokeDate] :
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
    if(result.empty()) return nullptr;
    return result[0];
  } catch (...) {
    throw;
  }
}

CertificateAuthorityModelPtr PgDatabase::GetCa(const std::string &serial) {

  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query =
        "SELECT \"serial\", \"thumbprint\", \"commonName\", "
        "\"issueDate\", \"certificate\", \"privateKey\", \"publicUrl\" "
        "FROM ca "
        "WHERE UPPER(\"serial\") = UPPER($1) "
        "ORDER BY \"issueDate\" LIMIT 1";
    pqxx::work tran(*conn);

    std::vector<CertificateAuthorityModelPtr> result;
    for (auto [serial, thumbprint, commonName, issueDate, certificate,
               privateKey, publicUrl] :
         tran.query<std::string_view, std::string_view, std::string_view,
                    std::string_view, pqxx::bytes, pqxx::bytes,
                    std::string_view>(query, {serial})) {
      auto model = std::make_shared<CertificateAuthorityModel>();
      model->serial = serial;
      model->thumbprint = thumbprint;
      model->commonName = commonName;
      model->issueDate = issueDate;
      model->certificate =
          std::vector<std::byte>(certificate.begin(), certificate.end());
      model->privateKey =
          std::vector<std::byte>(privateKey.begin(), privateKey.end());
      model->publicUrl = publicUrl;
      result.push_back(model);
    }
    tran.commit();
    if (result.empty())
      return nullptr;
    return result[0];
  } catch (...) {
    throw;
  }
}

std::vector<CertificateAuthorityModelPtr> PgDatabase::GetAllCa() {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    std::vector<CertificateAuthorityModelPtr> result;
    static auto query =
        "SELECT \"serial\", \"thumbprint\", \"commonName\", "
        "\"issueDate\", \"certificate\", \"privateKey\", \"publicUrl\" "
        "FROM ca";
    pqxx::work tran(*conn);

    for (auto [serial, thumbprint, commonName, issueDate, certificate,
               privateKey, publicUrl] :
         tran.query<std::string_view, std::string_view, std::string_view,
                    std::string_view, pqxx::bytes, pqxx::bytes,
                    std::string_view>(query)) {
      auto model = std::make_shared<CertificateAuthorityModel>();
      model->serial = serial;
      model->thumbprint = thumbprint;
      model->commonName = commonName;
      model->issueDate = issueDate;
      model->certificate =
          std::vector<std::byte>(certificate.begin(), certificate.end());
      model->privateKey =
          std::vector<std::byte>(privateKey.begin(), privateKey.end());
      model->publicUrl = publicUrl;
      result.push_back(model);
    }
    tran.commit();
    return result;
  } catch (...) {
    throw;
  }
}

void PgDatabase::AddCertificate(const CertificateModel &cert) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query =
        "INSERT INTO certificates(\"serial\", \"thumbprint\", \"caSerial\", "
        "\"commonName\", \"issueDate\", \"revokeDate\") "
        "VALUES ($1, $2, $3, $4, $5, $6)";
    conn->prepare("insert_cert", query);
    pqxx::work tran(*conn);
    auto result = tran.exec_prepared("insert_cert", cert.serial,
                                     cert.thumbprint, cert.caSerial,
                                     cert.commonName, cert.issueDate, nullptr);
    tran.commit();
  } catch (...) {
    throw;
  }
}

void PgDatabase::AddCA(const CertificateAuthorityModel &ca) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
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
    throw;
  }
}

void PgDatabase::MakeCertificateRevoked(const std::string &serial,
                                        const std::string &revokeDate) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query = "UPDATE certificates SET \"revokeDate\" = $1"
                        "WHERE UPPER(serial) = UPPER($2)";
    conn->prepare("revoke_cert", query);
    pqxx::work tran(*conn);
    auto result = tran.exec_prepared("revoke_cert", serial, revokeDate);
    tran.commit();
  } catch (...) {
    throw;
  }
}

void PgDatabase::AddCrl(const CrlModel &crl) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    static auto query = "INSERT INTO crl(\"caSerial\", \"number\", "
                        "\"issueDate\", \"lastSerial\", \"content\") "
                        "VALUES ($1, $2, $3, $4, $5)";
    conn->prepare("insert_crl", query);
    pqxx::work tran(*conn);
    auto result = tran.exec_prepared(
        "insert_crl", crl.caSerial, crl.number, crl.issueDate, crl.lastSerial,
        pqxx::binary_cast(crl.content.data(), crl.content.size()));
    tran.commit();

  } catch (...) {
    throw;
  }
}
CrlModelPtr PgDatabase::GetActualCrl(const std::string &caSerial) {
  try {
    ConnectionScope scope(_connectionPool);
    auto conn = scope.GetConnection();
    std::vector<CrlModelPtr> result;
    static auto query =
        "SELECT \"caSerial\", \"number\", \"issueDate\", \"lastSerial\", \"content\" "
        "FROM crl "
        "WHERE UPPER(\"caSerial\") = UPPER($1)"
        "ORDER BY number DESC LIMIT 1";
    pqxx::work tran(*conn);
    for(auto[caSerial, number, issueDate, lastSerial, content] : tran.query<std::string_view, long, std::string_view, std::string_view, pqxx::bytes>(query, caSerial)) {
      auto model = std::make_shared<CrlModel>();
      model->caSerial = caSerial;
      model->number = number;
      model->issueDate = issueDate;
      model->lastSerial = lastSerial;
      model->content = std::vector(content.begin(), content.end());
      result.push_back(model);
    }
    if(result.empty()) return nullptr;
    return result[0];
  } catch (...) {
    throw;
  }
}
