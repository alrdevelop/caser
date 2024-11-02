#ifndef _CASERV_JSON_TYPE_SPEC_CERTIFICATE_MODEL_SPEC_H_
#define _CASERV_JSON_TYPE_SPEC_CERTIFICATE_MODEL_SPEC_H_

#include "./../../contracts/certificate_model.h"
#include "./../json.hpp"

namespace contracts {

using json = nlohmann::json;

// inline void from_json(const json &json, CertificateModelPtr &model) {

// }

inline void to_json(json &j, const CertificateModelPtr &model) {
  j["serial"] = model->serial;
  j["thumbprint"] = model->thumbprint;
  j["caSerial"] = model->caSerial;
  j["commonName"] = model->commonName;
  j["issueDate"] = datetime::to_utcstring(model->issueDate);
  if (model->revokeDate != nullptr)
    j["revokeDate"] = datetime::to_utcstring(model->revokeDate);
}

inline void to_json(json &j, const StoredCertificateAuthorityModelPtr &model) {
  j["serial"] = model->serial;
  j["thumbprint"] = model->thumbprint;
  j["commonName"] = model->commonName;
  j["issueDate"] = datetime::to_utcstring(model->issueDate);
  j["publicUrl"] = model->publicUrl;
}


} // namespace contracts

#endif //_CASERV_JSON_TYPE_SPEC_CERTIFICATE_MODEL_SPEC_H_
