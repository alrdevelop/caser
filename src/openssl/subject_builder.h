#ifndef _CASERV_OPENSSL_SUBJECT_BUILDER_H_
#define _CASERV_OPENSSL_SUBJECT_BUILDER_H_

#include <string_view>
#include <vector>

#include "./../contracts/certificate_request.h"

namespace openssl {
namespace _ {

using namespace contracts;

template <typename TReq> struct BaseCertificateSubjectBuilder {
  virtual ~BaseCertificateSubjectBuilder() = default;
  virtual std::vector<std::pair<std::string_view, std::string_view>>
  SubjectName(const TReq &req) = 0;
};

struct CertificateSubjectBuilder
    : public BaseCertificateSubjectBuilder<CertificateRequestBase> {
  std::vector<std::pair<std::string_view, std::string_view>>
  SubjectName(const CertificateRequestBase &req) {
    return std::vector<std::pair<std::string_view, std::string_view>>{
        {"CN", req.commonName},
        {"C", req.country},
        {"localityName", req.localityName},
        {"stateOrProvinceName", req.stateOrProvinceName},
        {"streetAddress", req.streetAddress},
        {"emailAddress", req.emailAddress},
    };
  }
};

struct PhysicalPersonCertificateSubjectBuilder
    : public BaseCertificateSubjectBuilder<PhysicalPersonCertificateRequest>,
      CertificateSubjectBuilder {
  std::vector<std::pair<std::string_view, std::string_view>>
  SubjectName(const PhysicalPersonCertificateRequest &req) {
    auto result = CertificateSubjectBuilder::SubjectName(req);
    result.push_back({"INN", req.inn});
    result.push_back({"SNILS", req.snils});
    result.push_back({"givenName", req.givenName});
    result.push_back({"surname", req.surname});
    return result;
  }
};

struct IndividualEntrepreneurCertificateSubjectBuilder
    : public BaseCertificateSubjectBuilder<
          IndividualEntrepreneurCertificateRequest>,
      PhysicalPersonCertificateSubjectBuilder {
  std::vector<std::pair<std::string_view, std::string_view>>
  SubjectName(const IndividualEntrepreneurCertificateRequest &req) {
    auto result = PhysicalPersonCertificateSubjectBuilder::SubjectName(req);
    result.push_back({"OGRNIP", req.ogrnip});
    return result;
  }
};

struct JuridicalPersonCertificateSubjectBuilder
    : public BaseCertificateSubjectBuilder<JuridicalPersonCertificateRequest>,
      PhysicalPersonCertificateSubjectBuilder {
  std::vector<std::pair<std::string_view, std::string_view>>
  SubjectName(const JuridicalPersonCertificateRequest &req) {
    auto result = PhysicalPersonCertificateSubjectBuilder::SubjectName(req);
    result.push_back({"1.2.643.100.4", req.innLe}); // INN_LE
    result.push_back({"OGRN", req.ogrn});
    result.push_back({"O", req.organizationName});
    result.push_back({"OU", req.organizationUnitName});
    result.push_back({"title", req.title});
    return result;
  }
};

} // namespace _

} // namespace openssl

#endif //_CASERV_OPENSSL_SUBJECT_BUILDER_H_