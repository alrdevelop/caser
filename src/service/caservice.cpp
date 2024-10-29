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
  auto dt = datetime_now();
  data.issueDate = std::string_view(dt);

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
  auto dt = datetime_now();
  model.issueDate = std::string_view(dt);
  _db->AddCertificate(model);
}