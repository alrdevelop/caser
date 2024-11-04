#include "caservice.h"
#include <cstddef>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <utility>
#include <vector>

#include "./../common/datetime.h"
#include "./../common/logger.h"
#include "models/models.h"

using namespace serivce;


const PhysicalPersonCertificateRequest& Map(PhysicalPersonCertificateRequest &dst, const IssueCertificateModel &src){
  dst.algorithm = src.algorithm;
  dst.commonName = src.commonName;
  dst.country = src.country;
  dst.localityName = src.localityName;
  dst.stateOrProvinceName = src.stateOrProvinceName;
  dst.streetAddress = src.streetAddress;
  dst.emailAddress = src.emailAddress;
  dst.ttlInDays = src.ttlInDays;
  dst.inn = src.inn;
  dst.snils = src.snils;
  dst.givenName = src.givenName;
  dst.surname = src.surname;
  return dst;
}

const IndividualEntrepreneurCertificateRequest& Map(IndividualEntrepreneurCertificateRequest &dst, const IssueCertificateModel &src) {
  Map(static_cast<PhysicalPersonCertificateRequest&>(dst), src);
  dst.ogrnip = src.ogrnip;
  return dst;
}

const JuridicalPersonCertificateRequest& Map(JuridicalPersonCertificateRequest &dst, const IssueCertificateModel &src) {
  Map(static_cast<PhysicalPersonCertificateRequest&>(dst), src);
  dst.innLe = src.innLe;
  dst.ogrn = src.ogrn;
  dst.organizationName = src.organizationName;
  dst.organizationUnitName = src.organizationUnitName;
  dst.title = src.title;
  return dst;
}

CaService::CaService(IDataBasePtr db, ICryptoProviderUPtr crypto) : _db(db) {
  _crypto = std::move(crypto);
}

CaService::~CaService() {}

StoredCertificateModelPtr CaService::GetCertificate(const std::string &serial) {
  auto model = _db->GetCertificate(serial);
  if (model != nullptr) {
    auto result = std::make_shared<StoredCertificateModel>();
    result->caSerial = model->caSerial;
    result->serial = model->serial;
    result->thumbprint = model->thumbprint;
    result->commonName = model->commonName;
    result->issueDate = model->issueDate;
    result->revokeDate = model->revokeDate;
    return result;
  }
  return nullptr;
}
std::vector<StoredCertificateModelPtr>
CaService::GetCertificates(const std::string &caSerial) {
  auto result = std::vector<StoredCertificateModelPtr>();
  auto models = _db->GetCertificates(caSerial);
  for (auto m : models) {
    auto cert = std::make_shared<StoredCertificateModel>();
    cert->caSerial = m->caSerial;
    cert->serial = m->serial;
    cert->thumbprint = m->thumbprint;
    cert->commonName = m->commonName;
    cert->issueDate = m->issueDate;
    cert->revokeDate = m->revokeDate;
    result.push_back(cert);
  }
  return result;
}
std::vector<StoredCertificateModelPtr> CaService::GetAllCertificates() {
  auto result = std::vector<StoredCertificateModelPtr>();
  auto models = _db->GetAllCertificates();
  for (auto m : models) {
    auto cert = std::make_shared<StoredCertificateModel>();
    cert->caSerial = m->caSerial;
    cert->serial = m->serial;
    cert->thumbprint = m->thumbprint;
    cert->commonName = m->commonName;
    cert->issueDate = m->issueDate;
    cert->revokeDate = m->revokeDate;
    result.push_back(cert);
  }
  return result;
}

StoredCertificateAuthorityModelPtr CaService::GetCa(const std::string &serial) {
  auto model = _db->GetCa(serial);
  auto result = std::make_shared<StoredCertificateAuthorityModel>();
  result->serial = std::string_view(model->serial.data());
  result->thumbprint = std::string_view(model->thumbprint.data());
  result->commonName = std::string_view(model->commonName.data());
  result->issueDate = model->issueDate;
  result->publicUrl = std::string_view(model->publicUrl);
  return result;
}

std::vector<std::byte>
CaService::GetCaCertificateData(const std::string &serial) {
  return _db->GetCaCertificateData(serial);
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
  JuridicalPersonCertificateRequest req;
  req.commonName = model.commonName;
  req.country = model.country;
  req.stateOrProvinceName = model.stateOrProvinceName;
  req.localityName = model.localityName;
  req.streetAddress = model.streetAddress;
  req.emailAddress = model.emailAddress;
  req.innLe = model.innLe;
  req.ogrn = model.ogrn;
  req.organizationName = model.organizationName;
  req.algorithm = model.algorithm;

  auto caCert = _crypto->GeneratedCACertificate(req);
  CertificateAuthorityModel data{.serial = caCert->serialNumber,
                                 .thumbprint = caCert->thumbprint,
                                 .commonName = model.commonName,
                                 .certificate = caCert->certificate,
                                 .privateKey = caCert->privateKey,
                                 .publicUrl = model.publicUrl};
  auto dt = datetime::utc_now();
  data.issueDate = dt;

  _db->AddCA(data);
  return GetCa(caCert->serialNumber);
}

PKCS12ContainerUPtr
CaService::CreateClientCertificate(const std::string_view &caSerial,
                                   const IssueCertificateModel &model) {
  auto caInfo = GetCaInfo(caSerial);
  PKCS12ContainerUPtr container{nullptr};

  if(model.subjectType == SujectTypeEnum::PhysicalPerson) {
    auto req = new PhysicalPersonCertificateRequest();
    container = _crypto->GenerateClientCertitificate(Map(*req,model), caInfo);
    delete req;
  } else if ( model.subjectType == SujectTypeEnum::IndividualEntrepreneur) {
    auto req = new IndividualEntrepreneurCertificateRequest();
    container = _crypto->GenerateClientCertitificate(Map(*req,model), caInfo);
    delete req;
  } else if (model.subjectType == SujectTypeEnum::JuridicalPerson) {
    auto req = new JuridicalPersonCertificateRequest();
    container = _crypto->GenerateClientCertitificate(Map(*req,model), caInfo);
    delete req;
  } else {
    LOG_ERROR("SubjectTypeEnum value: {} not supported.",
              (int)model.subjectType);
    throw std::runtime_error("Invalid SubjectTypeEnum value");
  }

  if (container == nullptr)
    throw std::runtime_error("Container is null");
  SaveClientCertificate(caSerial, model.commonName, container);
  return std::move(container);
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
  // TODO: optimize db call
  auto crlInfo = _db->GetActualCrl(caSerial);
  auto caInfo = GetCaInfo(caSerial);
  long number = 1;
  if (crlInfo != nullptr) {
    number = crlInfo->number + 1;
  }
  auto revokedCerts = _db->GetRevokedListOrderByRevokeDateDesc(caSerial);
  CrlRequest req;
  req.number = number;
  for (auto cert : revokedCerts) {
    req.entries.push_back(CrlEntry{.serialNumber = cert->serial.data(),
                                   .revokationDate = cert->revokeDate});
  }
  std::sort(req.entries.begin(), req.entries.end(),
            [](const CrlEntry &a, const CrlEntry &b) {
              return *a.revokationDate <= *b.revokationDate;
            });
  std::string serial;
  auto crl = _crypto->GenerateCrl(req, caInfo);
  auto dtNow = datetime::utc_now();
  CrlModel model{.caSerial = caSerial,
                 .number = number,
                 .issueDate = dtNow,
                 .content = crl.get()->content};
  if (!req.entries.empty()) {
    serial = req.entries[req.entries.size() - 1].serialNumber;
    model.lastSerial = serial;
  }
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