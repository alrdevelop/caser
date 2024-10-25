#ifndef _CASERV_OPENSSL_CRYPTO_PROVIDER_H_
#define _CASERV_OPENSSL_CRYPTO_PROVIDER_H_

#include "./../base/icrypto_provider.h"
#include "subject_builder.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <map>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
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

private:
  using EvpPkeyUPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
  using X509Uptr = std::unique_ptr<X509, decltype(&::X509_free)>;
  using X509CrlUptr = std::unique_ptr<X509_CRL, decltype(&::X509_CRL_free)>;

  EvpPkeyUPtr GenerateKeyPair(const PkeyParams &params);
  CertificateUPtr GenerateX509Certitificate(const AlgorithmEnum &algorithm,const std::vector<std::pair<std::string_view, std::string_view>> &subject, const long &ttlInDays, const CaInfo* caInfo);
};
} // namespace openssl

#endif //_CASERV_OPENSSL_CRYPTO_PROVIDER_H_