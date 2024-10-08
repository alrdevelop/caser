#ifndef _CASERV_OPENSSL_PROVIDER_H_
#define _CASERV_OPENSSL_PROVIDER_H_

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <new>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/txt_db.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "db.h"
#include "defines.h"
#include "error_text.h"

#include "./../contracts/certificate_request.h"

namespace openssl {
using namespace contracts;

using EvpPkeyUPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509Uptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using X509CrlUptr = std::unique_ptr<X509_CRL, decltype(&::X509_CRL_free)>;
using ParamsSet = std::vector<std::pair<std::string, std::string>>;

#define SERIAL_LEN 16 // 128 bit

struct PkeyParams {
  int keytype;
  int p1;
  int digest;
};

static std::unordered_map<contracts::AlgorithmEnum, PkeyParams> PkeyOptions{
    {contracts::AlgorithmEnum::GostR3410_2012_256,
     {.keytype = NID_id_GostR3410_2012_256,
      .p1 = NID_id_tc26_gost_3410_2012_256_paramSetA,
      .digest = NID_id_GostR3411_2012_256}},
    {contracts::AlgorithmEnum::GostR3410_2012_512,
     {.keytype = NID_id_GostR3410_2012_512,
      .p1 = NID_id_tc26_gost_3410_2012_512_paramSetA,
      .digest = NID_id_GostR3411_2012_512}}};

// use basic params for CA root cert
static std::map<int, const char *> CaExtensions{
    {NID_subject_key_identifier, "hash"},
    {NID_authority_key_identifier, "keyid:always"},
    {NID_basic_constraints, "CA:TRUE,pathlen:0"},
    {NID_key_usage, "critical,cRLSign,digitalSignature,keyCertSign"},
    {NID_certificate_policies,
     "1.2.643.100.113.1,1.2.643.100.113.2,anyPolicy"}};

static std::map<int, const char *> ClientExtensions{
    {NID_subject_key_identifier, "hash"},
    {NID_authority_key_identifier, "keyid,issuer"},
    // {NID_basic_constraints, "critical"},
    {NID_key_usage, "critical, digitalSignature"},
    {NID_ext_key_usage, "clientAuth,"
                        "emailProtection,"
                        "1.2.643.2.2.34.6,"
                        "1.2.643.3.88.3.6,"
                        "1.2.643.3.88.1.1.1.7,"
                        "1.2.643.3.88.1.1.1.9,"
                        "1.2.643.3.88.1.1.1.10,"
                        "1.2.643.3.88.1.1.1.11"}};

class Provider {
public:
  Provider(ENGINE *engine) : _engine(engine) {}

  ~Provider() = default;

  std::pair<X509Uptr, EvpPkeyUPtr> GenerateX509Certitificate(
      const contracts::JuridicalPersonCertificateRequest &req,
      X509 *issuer = nullptr, EVP_PKEY *issuerKp = nullptr) {
    try {
      auto subject = Build(req);
      return GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays,
                                       issuer, issuerKp);
    } catch (...) {
      throw std::runtime_error("GenerateX509Certitificate failed.");
    }
  }

private:
  EvpPkeyUPtr GenerateKeyPair(const PkeyParams &params) {
    EVP_PKEY *pkey{EVP_PKEY_new()};
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

  std::pair<X509Uptr, EvpPkeyUPtr>
  GenerateX509Certitificate(const AlgorithmEnum &algorithm,
                            const ParamsSet &subject, const uint16_t ttlInDays,
                            X509 *issuer = nullptr,
                            EVP_PKEY *issuerKp = nullptr) {
    try {
      auto pkeyParamsIt = PkeyOptions.find(algorithm);
      if (pkeyParamsIt == PkeyOptions.end()) {
        LOG_ERROR("Unsupported algorithm {}.", (int)algorithm);
        throw std::runtime_error("Unsupported AlgorithmEnum.");
      }

      auto params = pkeyParamsIt->second;
      auto key = GenerateKeyPair(params);
      if (issuerKp == nullptr)
        issuerKp = key.get();
      auto cert = X509_new();

      // set serial number
      // ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
      ASN1_STRING *serialNumber = X509_get_serialNumber(cert);
      std::vector<uint8_t> serial(SERIAL_LEN);
      OSSL_CHECK(RAND_bytes(serial.data(), SERIAL_LEN));
      OSSL_CHECK(ASN1_STRING_set(serialNumber, serial.data(), SERIAL_LEN));

      // 0x00 - v1, 0x01 - v2, 0x02 - v3
      OSSL_CHECK(X509_set_version(cert, 0x02));
      // set dates
      X509_gmtime_adj(X509_get_notBefore(cert), 0);
      auto ttlSeconds = 86400L * ttlInDays;
      X509_gmtime_adj(X509_get_notAfter(cert), ttlSeconds);

      // Set certificate subject data
      X509_NAME *name = X509_get_subject_name(cert);
      for (auto subjPair : subject) {
        NameAddEntry(name, subjPair.first.c_str(), subjPair.second);
      }

      // set public key
      OSSL_CHECK(X509_set_pubkey(cert, key.get()));

      // set issuer
      // if issuer is null, create self signed cert
      if (issuer == nullptr)
        issuer = cert;
      auto issuerName = X509_get_subject_name(issuer);
      OSSL_CHECK(X509_set_issuer_name(cert, issuerName));

      auto extensions = issuer == cert ? CaExtensions : ClientExtensions;

      // Init context
      X509V3_CTX ctx;
      // setup context
      X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);

      // setup db and db_meth, we need it for certificate policies
      X509V3_CONF_METHOD conf;
      openssl::Database db;
      conf.get_string = openssl::db_get_string;
      conf.get_section = openssl::db_get_section;
      conf.free_string = openssl::db_free_string;
      conf.free_section = openssl::db_free_section;
      ctx.db = &db;
      ctx.db_meth = &conf;

      // setup extensions
      for (auto extIt : extensions) {
        auto ext =
            X509V3_EXT_conf_nid(nullptr, &ctx, extIt.first, extIt.second);
        if (ext != nullptr) {
          OSSL_CHECK(X509_add_ext(cert, ext, -1));
          X509_EXTENSION_free(ext);
        } else {
          LOG_WARNING("Failed to add cerificate extensions. NID: {}, "
                      "extensions: {}. Error: {}.",
                      extIt.first, extIt.second, openssl::get_errors_string());
        }
      }
      // sign cert
      const EVP_MD *md = EVP_get_digestbynid(params.digest); // EVP_get_digestbyname(SN_id_GostR3411_2012_512);
      OSSL_CHECK(X509_sign(cert, issuerKp, md));

      return std::make_pair(std::move(X509Uptr(cert, ::X509_free)),
                            std::move(key));

    } catch (...) {
      throw std::runtime_error("GenerateX509Certitificate failed.");
    }
  }

  X509CrlUptr CreateCRL() {}

  inline ParamsSet Build(const CertificateRequestBase &req) {
    return ParamsSet{
        {"CN", req.commonName},
        {"C", req.country},
        {"localityName", req.localityName},
        {"stateOrProvinceName", req.stateOrProvinceName},
        {"streetAddress", req.streetAddress},
        {"emailAddress", req.emailAddress},
    };
  }

  ParamsSet Build(const PhysicalPersonCertificateRequest &req) {
    auto result = Build(static_cast<CertificateRequestBase>(req));
    result.push_back({"INN", req.inn});
    result.push_back({"SNILS", req.snils});
    result.push_back({"givenName", req.givenName});
    result.push_back({"surname", req.surname});
    return result;
  }

  ParamsSet Build(const JuridicalPersonCertificateRequest &req) {
    auto result = Build(static_cast<PhysicalPersonCertificateRequest>(req));
    result.push_back({"1.2.643.100.4", req.innLe}); // INN_LE
    result.push_back({"OGRN", req.ogrn});
    result.push_back({"O", req.organizationName});
    result.push_back({"OU", req.organizationUnitName});
    result.push_back({"title", req.title});
    return result;
  }

  ParamsSet Build(const IndividualEntrepreneurCertificateRequest &req) {
    auto result = Build(static_cast<PhysicalPersonCertificateRequest>(req));
    result.push_back({"OGRNIP", req.ogrnip});
    return result;
  }

  /*
    Add subject entry
  */
  inline void NameAddEntry(X509_NAME *name, const char *field,
                           const std::string &val, int type = MBSTRING_UTF8) {
    if (val.empty())
      return;
    OSSL_CHECK(X509_NAME_add_entry_by_txt(
        name, field, type, (unsigned char *)val.c_str(), -1, -1, 0));
  }

private:
  ENGINE *_engine;
};
} // namespace openssl

#endif //_CASERV_OPENSSL_PROVIDER_H_
