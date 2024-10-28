#ifndef _CASERV_BASE_CRYPTO_PROVIDER_H_
#define _CASERV_BASE_CRYPTO_PROVIDER_H_

#include "./../contracts/generated_certificate.h"
#include "./../contracts/certificate_request.h"
#include "./../contracts/ca_info.h"
#include <memory>

namespace base {

using namespace contracts;
class ICryptoProvider {
public:
  virtual ~ICryptoProvider() = default;
  virtual PKCS12ContainerUPtr GenerateClientCertitificate(const PhysicalPersonCertificateRequest& req, const CaInfo& caInfo) = 0;
  virtual PKCS12ContainerUPtr GenerateClientCertitificate(const IndividualEntrepreneurCertificateRequest& req, const CaInfo& caInfo) = 0;
  virtual PKCS12ContainerUPtr GenerateClientCertitificate(const JuridicalPersonCertificateRequest& req, const CaInfo& caInfo) = 0;
  virtual CertificateUPtr GeneratedCACertificate(const JuridicalPersonCertificateRequest& req) = 0;
};

using ICryptoProviderUPtr = std::unique_ptr<ICryptoProvider>;

} // namespace base

#endif //_CASERV_BASE_CRYPTO_PROVIDER_H_