#ifndef _CASERV_SERVICE_MODELS_H_
#define _CASERV_SERVICE_MODELS_H_

#include <ctime>
#include <memory>
#include <string>

#include "./../../common/datetime.h"
#include "./../../contracts/enums.h"
#include "./../../libs/json.hpp"

namespace service {
namespace models {

using namespace datetime;
using namespace contracts;

struct CreateCertificateAuthorityModel {
  AlgorithmEnum algorithm{AlgorithmEnum::GostR3410_2012_256};
  std::string country{"RU"};
  std::string localityName;
  std::string stateOrProvinceName;
  std::string streetAddress;
  std::string emailAddress;
  std::string innLe;
  std::string ogrn;
  std::string organizationName;
  uint16_t ttlInDays{365};
  std::string publicUrl;
};

struct StoredCertificateAuthorityModel {
  std::string serial;
  std::string thumbprint;
  std::string commonName;
  DateTimePtr issueDate;
  std::string publicUrl;
};

struct StoredCertificateModel {
  std::string serial;
  std::string thumbprint;
  std::string caSerial;
  std::string commonName;
  DateTimePtr issueDate;
  DateTimePtr revokeDate;
};

struct IssueCertificateModel {
  SujectTypeEnum subjectType{SujectTypeEnum::PhysicalPerson};
  AlgorithmEnum algorithm{AlgorithmEnum::GostR3410_2012_256};
  uint16_t ttlInDays{365};
  std::string country{"RU"};
  std::string localityName;
  std::string stateOrProvinceName;
  std::string streetAddress;
  std::string emailAddress;
  std::string inn;
  std::string snils;
  std::string givenName;
  std::string surname;
  std::string ogrnip;
  std::string innLe;
  std::string ogrn;
  std::string organizationName;
  std::string organizationUnitName;
  std::string title;
  std::string pin;
};

using CreateCertificateAuthorityModelPtr =
    std::shared_ptr<CreateCertificateAuthorityModel>;
using StoredCertificateAuthorityModelPtr =
    std::shared_ptr<StoredCertificateAuthorityModel>;
using StoredCertificateModelPtr = std::shared_ptr<StoredCertificateModel>;
using IssueCertificateModelPtr = std::shared_ptr<IssueCertificateModel>;

// TODO move to separated files
using json = nlohmann::json;

inline void from_json(const json &json, IssueCertificateModelPtr &model) {
  json.at("subjectType").get_to(model->subjectType);
  json.at("algorithm").get_to(model->algorithm);
  json.at("ttlInDays").get_to(model->ttlInDays);
  json.at("country").get_to(model->country);
  json.at("localityName").get_to(model->localityName);
  json.at("stateOrProvinceName").get_to(model->stateOrProvinceName);
  json.at("streetAddress").get_to(model->streetAddress);
  json.at("emailAddress").get_to(model->emailAddress);
  json.at("inn").get_to(model->inn);
  json.at("snils").get_to(model->snils);
  json.at("givenName").get_to(model->givenName);
  json.at("surname").get_to(model->surname);
  json.at("ogrnip").get_to(model->ogrnip);
  json.at("innLe").get_to(model->innLe);
  json.at("ogrn").get_to(model->ogrn);
  json.at("organizationName").get_to(model->organizationName);
  json.at("organizationUnitName").get_to(model->organizationUnitName);
  json.at("title").get_to(model->title);
}

template<typename KeyType, typename ValueType>
ValueType& try_get_to(const json& j, const KeyType& key, ValueType& value) {
  if(j.contains(key)) j.at(key).get_to(value);
}

//TODO: add validation for json model
inline void from_json(const json &json, IssueCertificateModel &model) {
  json.at("subjectType").get_to(model.subjectType);
  json.at("algorithm").get_to(model.algorithm);
  json.at("ttlInDays").get_to(model.ttlInDays);
  
  if(json.contains("country")) json.at("country").get_to(model.country);
  if(json.contains("localityName")) json.at("localityName").get_to(model.localityName);
  if(json.contains("stateOrProvinceName")) json.at("stateOrProvinceName").get_to(model.stateOrProvinceName);
  if(json.contains("streetAddress")) json.at("streetAddress").get_to(model.streetAddress);
  if(json.contains("emailAddress")) json.at("emailAddress").get_to(model.emailAddress);
  if(json.contains("inn")) json.at("inn").get_to(model.inn);
  if(json.contains("snils")) json.at("snils").get_to(model.snils);
  if(json.contains("givenName")) json.at("givenName").get_to(model.givenName);
  if(json.contains("surname")) json.at("surname").get_to(model.surname);
  if(json.contains("ogrnip")) json.at("ogrnip").get_to(model.ogrnip);
  if(json.contains("innLe")) json.at("innLe").get_to(model.innLe);
  if(json.contains("ogrn")) json.at("ogrn").get_to(model.ogrn);
  if(json.contains("organizationName")) json.at("organizationName").get_to(model.organizationName);
  if(json.contains("organizationUnitName")) json.at("organizationUnitName").get_to(model.organizationUnitName);
  if(json.contains("title")) json.at("title").get_to(model.title);
}

inline void from_json(const json &json, CreateCertificateAuthorityModel &model) {
  json.at("algorithm").get_to(model.algorithm);
  json.at("ttlInDays").get_to(model.ttlInDays);
  json.at("publicUrl").get_to(model.publicUrl);
  
  if(json.contains("country")) json.at("country").get_to(model.country);
  if(json.contains("localityName")) json.at("localityName").get_to(model.localityName);
  if(json.contains("stateOrProvinceName")) json.at("stateOrProvinceName").get_to(model.stateOrProvinceName);
  if(json.contains("streetAddress")) json.at("streetAddress").get_to(model.streetAddress);
  if(json.contains("emailAddress")) json.at("emailAddress").get_to(model.emailAddress);
  if(json.contains("innLe")) json.at("innLe").get_to(model.innLe);
  if(json.contains("ogrn")) json.at("ogrn").get_to(model.ogrn);
  if(json.contains("organizationName")) json.at("organizationName").get_to(model.organizationName);
}

inline void to_json(json &j, const service::models::StoredCertificateModelPtr &model) {
  j["serial"] = model->serial;
  j["thumbprint"] = model->thumbprint;
  j["caSerial"] = model->caSerial;
  j["commonName"] = model->commonName;
  j["issueDate"] = datetime::to_utcstring(model->issueDate);
  if (model->revokeDate != nullptr)
    j["revokeDate"] = datetime::to_utcstring(model->revokeDate);
}

inline void
to_json(json &j,
        const service::models::StoredCertificateAuthorityModelPtr &model) {
  j["serial"] = model->serial;
  j["thumbprint"] = model->thumbprint;
  j["commonName"] = model->commonName;
  j["issueDate"] = datetime::to_utcstring(model->issueDate);
  j["publicUrl"] = model->publicUrl;
}

} // namespace models
} // namespace service

#endif //_CASERV_SERVICE_MODELS_H_
