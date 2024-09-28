#ifndef _CASERV_OPENSSL_PROVIDER_H_
#define _CASERV_OPENSSL_PROVIDER_H_

#include <cstdint>
#include <memory>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "defines.h"
#include "error_text.h"

#include "./../contracts/certificate_request.h"

namespace openssl {
using EvpPkeyUPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509Uptr = std::unique_ptr<X509, decltype(&::X509_free)>;

struct PkeyParams {
  int keytype;
  int p1;
};

static std::unordered_map<contracts::AlgorithmEnum, PkeyParams> PkeyOptions{
    {contracts::AlgorithmEnum::GostR3410_2012_256,
     {.keytype = NID_id_GostR3410_2012_256,
      .p1 = NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet}},
    {contracts::AlgorithmEnum::GostR3410_2012_512,
     {.keytype = NID_id_GostR3410_2012_512,
      .p1 = NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet}}};

class Provider {
public:
  Provider(ENGINE *engine) : _engine(engine) {}

  ~Provider() = default;

  EvpPkeyUPtr GenerateKeyPair(const contracts::AlgorithmEnum &algo) {
    EVP_PKEY *pkey{EVP_PKEY_new()};
    auto pkeyParamsIt = PkeyOptions.find(algo);
    if (pkeyParamsIt == PkeyOptions.end()) {
      LOG_ERROR("GenerateKeyPair failed. Unsupported algorithm {}.", (int)algo);
      throw std::runtime_error(
          "GenerateKeyPair failed. Unsupported algorithm.");
    }

    auto params = pkeyParamsIt->second;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(params.keytype, _engine);
    if (ctx == nullptr) {
      LOG_ERROR("EVP_PKEY_CTX_new_id fail. {}", openssl::get_errors_string());
      throw std::runtime_error("EVP_PKEY_CTX_new_id fail.");
    }

    try {
      OSSL_CHECK(EVP_PKEY_paramgen_init(ctx));
      OSSL_CHECK(EVP_PKEY_CTX_ctrl(ctx, params.keytype, EVP_PKEY_OP_PARAMGEN,
                                   EVP_PKEY_CTRL_GOST_PARAMSET, params.p1,
                                   NULL));
      OSSL_CHECK(EVP_PKEY_paramgen_init(ctx));
      OSSL_CHECK(EVP_PKEY_keygen_init(ctx));
      OSSL_CHECK(EVP_PKEY_keygen(ctx, &pkey));
      return std::move(EvpPkeyUPtr(pkey, ::EVP_PKEY_free));
    } catch (...) {
      if (ctx != nullptr) {
        EVP_PKEY_CTX_free(ctx);
      }
      throw std::runtime_error("GenerateKeyPair failed.");
    }
  }

  X509Uptr GenerateX509Certitificate(const contracts::PhysicalPersonCertificateRequest &req, X509* issuer = nullptr) {
    try {
      auto key = GenerateKeyPair(req.algorithm);
      auto cert = X509_new();
      const EVP_MD *md = EVP_get_digestbyname(SN_id_GostR3411_2012_256);

      // set serial number
      // ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
      ASN1_STRING *serialNumber = X509_get_serialNumber(cert);
      std::vector<uint8_t> serial(20);
      OSSL_CHECK(RAND_bytes(serial.data(), 20));
      OSSL_CHECK(ASN1_STRING_set(serialNumber, serial.data(), 20));

      // 0x00 - v1, 0x01 - v2, 0x02 - v3
      OSSL_CHECK(X509_set_version(cert, 0x02));
      // set dates
      X509_gmtime_adj(X509_get_notBefore(cert), 0);
      auto ttlSeconds = 86400L * req.ttlInDays;
      X509_gmtime_adj(X509_get_notAfter(cert), ttlSeconds);

      // Set certificate data
      X509_NAME *name = X509_get_subject_name(cert);
      NameAddEntry(name, "C", req.country.c_str());
      NameAddEntry(name, "CN", req.commonName.c_str());
      NameAddEntry(name, "O", "ООО РОГА");

      // set public key
      OSSL_CHECK(X509_set_pubkey(cert, key.get()));

      // set issuer
      // if issuer is null, create self signed cert
      if(issuer == nullptr) issuer = cert;
      auto issuerName = X509_get_subject_name(issuer);
      OSSL_CHECK(X509_set_issuer_name(cert, issuerName));

      //sign cert
      OSSL_CHECK(X509_sign(cert, key.get(), md));

      return std::move(X509Uptr(cert, ::X509_free));

    } catch (...) {
      throw std::runtime_error("GenerateX509Certitificate failed.");
    }
  }

  void NameAddEntry(X509_NAME *name, const char* field, const std::string val, int type = MBSTRING_UTF8){
    if(val.empty()) return;
    OSSL_CHECK(X509_NAME_add_entry_by_txt(name, field, type, (unsigned char *)val.c_str(), -1, -1, 0));
  }

private:
  ENGINE *_engine;
};
} // namespace openssl

#endif //_CASERV_OPENSSL_PROVIDER_H_
