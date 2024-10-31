#include "caservice.h"
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "./../common/datetime.h"

using namespace serivce;

CaService::CaService(IDataBasePtr db, ICryptoProviderUPtr crypto) : _db(db) {
  _crypto = std::move(crypto);
}

CaService::~CaService() {}

CertificateModelPtr CaService::GetCertificate(const std::string &serial) {
  return _db->GetCertificate(serial);
}
std::vector<CertificateModelPtr>
CaService::GetCertificates(const std::string &caSerial) {
  return _db->GetCertificates(caSerial);
}
std::vector<CertificateModelPtr> CaService::GetAllCertificates() {
  return _db->GetAllCertificates();
}

StoredCertificateAuthorityModelPtr CaService::GetCa(const std::string &serial) {
  auto model = _db->GetCa(serial);
  auto result = std::make_shared<StoredCertificateAuthorityModel>();
  result->serial = model->serial;
  result->thumbprint = model->thumbprint;
  result->commonName = model->commonName;
  result->issueDate = model->issueDate;
  result->publicUrl = model->publicUrl;
  result->certificate = model->certificate;
  return result;
}

std::vector<StoredCertificateAuthorityModelPtr> CaService::GetAllCa() {
  std::vector<StoredCertificateAuthorityModelPtr> result;
  auto models = _db->GetAllCa();
  for (auto model : models) {
    auto entry = std::make_shared<StoredCertificateAuthorityModel>();
    entry->serial = model->serial;
    entry->thumbprint = model->thumbprint;
    entry->commonName = model->commonName;
    entry->issueDate = model->issueDate;
    entry->publicUrl = model->publicUrl;
    entry->certificate = model->certificate;
    result.push_back(entry);
  }
  return result;
}

StoredCertificateAuthorityModelPtr
CaService::CreateCA(const CreateCertificateAuthorityModel &model) {
  auto caCert = _crypto->GeneratedCACertificate(model.request);
  CertificateAuthorityModel data{.serial = caCert->serialNumber,
                                 .thumbprint = caCert->thumbprint,
                                 .commonName = model.request.commonName,
                                 .certificate = caCert->certificate,
                                 .privateKey = caCert->privateKey,
                                 .publicUrl = model.publicUrl};
  auto dt = datetime::utc_now();
  data.issueDate = dt;

  _db->AddCA(data);
  return GetCa(caCert->serialNumber);
}

PKCS12ContainerUPtr CaService::CreateClientCertificate(
    const std::string_view &caSerial,
    const JuridicalPersonCertificateRequest &req) {
  auto caInfo = GetCaInfo(caSerial);
  auto client = _crypto->GenerateClientCertitificate(req, caInfo);
  if (client == nullptr)
    throw std::runtime_error("Container is null");
  SaveClientCertificate(caSerial, req.commonName, client);
  return std::move(client);
}

PKCS12ContainerUPtr CaService::CreateClientCertificate(
    const std::string_view &caSerial,
    const IndividualEntrepreneurCertificateRequest &req) {
  auto caInfo = GetCaInfo(caSerial);
  auto client = _crypto->GenerateClientCertitificate(req, caInfo);
  if (client == nullptr)
    throw std::runtime_error("Container is null");
  SaveClientCertificate(caSerial, req.commonName, client);
  return std::move(client);
}

PKCS12ContainerUPtr CaService::CreateClientCertificate(
    const std::string_view &caSerial,
    const PhysicalPersonCertificateRequest &req) {
  auto caInfo = GetCaInfo(caSerial);
  auto client = _crypto->GenerateClientCertitificate(req, caInfo);
  if (client == nullptr)
    throw std::runtime_error("Container is null");
  SaveClientCertificate(caSerial, req.commonName, client);
  return std::move(client);
}

std::vector<std::byte> CaService::GetCrl(const std::string &caSerial) {
  auto crl = _db->GetActualCrl(caSerial);
  if (crl == nullptr)
    return InvalidateCrl(caSerial);
  auto lastRevoked = _db->GetLastRevoked(caSerial);
  if (lastRevoked != nullptr && crl->lastSerial != lastRevoked->serial)
    return InvalidateCrl(caSerial);
  return crl->content;
}

std::vector<std::byte> CaService::InvalidateCrl(const std::string &caSerial) {
  //TODO: optimize db call
  auto crlInfo = _db->GetActualCrl(caSerial);
  auto lastRevoked = _db->GetLastRevoked(caSerial);
  auto caInfo = GetCaInfo(caSerial);
  long number = 1;
  if(crlInfo != nullptr) {
    number = crlInfo->number + 1;
  }
  auto revokedCerts = _db->GetRevokedListOrderByRevokeDateDesc(caSerial);
  CrlRequest req;
  req.number = number;
  for(auto cert : revokedCerts) {
    req.entries.push_back(CrlEntry{
      .serialNumber = cert->serial,
      .revokationDate = cert->revokeDate
    });
  }
  auto crl = _crypto->GenerateCrl(req, caInfo);
  auto dtNow = datetime::utc_now();
  CrlModel model {
    .caSerial = caSerial,
    .number = number,
    .issueDate = dtNow,
    .content = crl.get()->content
  };
  if(lastRevoked != nullptr) model.lastSerial = lastRevoked->serial;
  _db->AddCrl(model);
  return crl.get()->content;
}

CaInfo CaService::GetCaInfo(const std::string_view &caSerial) {
  auto caCert = _db->GetCa(caSerial.data());
  if (caCert == nullptr)
    throw std::runtime_error("Cannot find CA.");
  auto crlUrl = std::format("{}/crl/{}.crl", caCert->publicUrl, caSerial);
  auto caEndpoint = std::format("{}/crt/{}.crt", caCert->publicUrl, caSerial);
  auto ocspEndpoint = std::format("{}/ocsp/{}", caCert->publicUrl, caSerial);
  CaInfo caInfo{
      .crlDistributionPoints = std::vector<std::string>{crlUrl},
      .ocspEndPoints = std::vector<std::string>{},
      .caEndPoints = std::vector<std::string>{caEndpoint},
      .privateKey = caCert->privateKey,
      .certificate = caCert->certificate,
  };
  return caInfo;
}

void CaService::SaveClientCertificate(const std::string_view &caSerial,
                                      const std::string_view &commonName,
                                      const PKCS12ContainerUPtr &container) {
  CertificateModel model;
  model.caSerial = caSerial;
  model.serial = container->serialNumber;
  model.thumbprint = container->thumbprint;
  model.commonName = commonName;
  auto dt = datetime::utc_now();
  model.issueDate = dt;
  _db->AddCertificate(model);
}