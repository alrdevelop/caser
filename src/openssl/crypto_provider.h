#ifndef _CASERV_OPENSSL_CRYPTO_PROVIDER_H_
#define _CASERV_OPENSSL_CRYPTO_PROVIDER_H_

#include "./../base/icrypto_provider.h"

#include <ctime>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/txt_db.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string_view>
#include <utility>
#include <vector>


namespace openssl {
using namespace base;
using namespace contracts;

#define SERIAL_LEN 16 // 128 bit

struct PkeyParams {
  int keytype;
  int p1;
  int digest;
};


class OpensslCryptoProvider : public ICryptoProvider {
public:
  OpensslCryptoProvider();
  virtual ~OpensslCryptoProvider();

  PKCS12ContainerUPtr
  GenerateClientCertitificate(const PhysicalPersonCertificateRequest &req,
                              const CaInfo &caInfo) override;

  PKCS12ContainerUPtr GenerateClientCertitificate(
      const IndividualEntrepreneurCertificateRequest &req,
      const CaInfo &caInfo) override;

  PKCS12ContainerUPtr
  GenerateClientCertitificate(const JuridicalPersonCertificateRequest &req,
                              const CaInfo &caInfo) override;

  CertificateUPtr
  GeneratedCACertificate(const JuridicalPersonCertificateRequest &req) override;
  CrlUPtr GenerateCrl(const CrlRequest& req, const CaInfo& CaInfo, const DateTimePtr &issueDate, const DateTimePtr &expireDate) override;

private:
  using EvpPkeyUPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
  using X509Uptr = std::unique_ptr<X509, decltype(&::X509_free)>;
  using X509CrlUptr = std::unique_ptr<X509_CRL, decltype(&::X509_CRL_free)>;

  EvpPkeyUPtr GenerateKeyPair(const PkeyParams &params);
  CertificateUPtr GenerateX509Certitificate(const AlgorithmEnum &algorithm,const std::vector<std::pair<std::string_view, std::string_view>> &subject, const long &ttlInDays, const CaInfo* caInfo);
  X509_REVOKED* CreateRevokedEntry(const std::string_view serial, const DateTime &revokeDate);
};
} // namespace openssl

#endif //_CASERV_OPENSSL_CRYPTO_PROVIDER_H_