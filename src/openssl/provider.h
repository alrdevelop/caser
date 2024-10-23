#ifndef _CASERV_OPENSSL_PROVIDER_H_
#define _CASERV_OPENSSL_PROVIDER_H_

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
#include <unordered_map>
#include <utility>
#include <vector>

#include "./../contracts/certificate_request.h"

#include "db.h"
#include "defines.h"
#include "error_text.h"

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

enum REVINFO_TYPE {
    REV_VALID             = -1, /* Valid (not-revoked) status */
    REV_NONE              = 0, /* No additional information */
    REV_CRL_REASON        = 1, /* Value is CRL reason code */
    REV_HOLD              = 2, /* Value is hold instruction */
    REV_KEY_COMPROMISE    = 3, /* Value is cert key compromise time */
    REV_CA_COMPROMISE     = 4  /* Value is CA key compromise time */
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
static std::map<int, std::string> CaExtensions{
    {NID_subject_key_identifier, "hash"},
    //{NID_authority_key_identifier, "keyid:always"},
    {NID_basic_constraints, "CA:TRUE,pathlen:0"},
    {NID_key_usage, "critical,cRLSign,digitalSignature,keyCertSign"},
    {NID_certificate_policies,
     "1.2.643.100.113.1,1.2.643.100.113.2,anyPolicy"}};

static std::map<int, std::string> ClientExtensions{
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

static std::map<int, std::string> CrlExtensions{
    {NID_authority_key_identifier, "keyid,issuer"},
    {NID_crl_number, "1"}
};
class Provider {
public:
  Provider(ENGINE *engine) : _engine(engine) {}

  ~Provider() = default;

  std::pair<X509Uptr, EvpPkeyUPtr> GenerateClientCertitificate(
      const contracts::JuridicalPersonCertificateRequest &req, X509 *issuer,
      EVP_PKEY *issuerKey) {
    try {
      auto subject = Build(req);
      std::vector<std::string> crlDistributionPoints{
          "https://test.ru/test.crl"};
      std::vector<std::string> ocspEndPoints{"https://test.ru/test.ocsp"};
      std::vector<std::string> caEndPoints{"https://test.ru/test.crt"};
      return GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays,
                                       crlDistributionPoints, ocspEndPoints,
                                       caEndPoints, issuer, issuerKey);
    } catch (...) {
      throw std::runtime_error("GenerateX509Certitificate failed.");
    }
  }

  std::pair<X509Uptr, EvpPkeyUPtr>
  GenerateCa(const contracts::JuridicalPersonCertificateRequest &req) {
    try {
      auto subject = Build(req);
      std::vector<std::string> crlDistributionPoints;
      std::vector<std::string> ocspEndPoints;
      std::vector<std::string> caEndPoints;
      return GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays,
                                       crlDistributionPoints, ocspEndPoints,
                                       caEndPoints);
    } catch (...) {
      throw std::runtime_error("GenerateCa failed.");
    }
  }

  X509CrlUptr CreateCRL(X509 *issuerCert, EVP_PKEY* issuerKp, const std::vector<X509 *> certs) {
    auto *asn1Tm = ASN1_UTCTIME_new();
    time_t now = time(0);
    ASN1_UTCTIME_adj(asn1Tm, now, 0, 0);

    auto crl = X509_CRL_new();
    OSSL_CHECK(X509_CRL_set_version(crl, X509_CRL_VERSION_2));
    OSSL_CHECK(X509_CRL_set_issuer_name(crl, X509_get_subject_name(issuerCert)));
    OSSL_CHECK(X509_CRL_set_lastUpdate(crl, asn1Tm));
    // ASN1_UTCTIME_adj(asn1Tm, now, 10, 0);
    OSSL_CHECK(X509_CRL_set_nextUpdate(crl, asn1Tm));

    for (auto cert : certs) {
      auto revoked = X509_REVOKED_new();
      auto serial = X509_get_serialNumber(cert);
      OSSL_CHECK(X509_REVOKED_set_serialNumber(revoked, X509_get_serialNumber(cert)));
      OSSL_CHECK(X509_REVOKED_set_revocationDate(revoked, asn1Tm));
      OSSL_CHECK(X509_CRL_add0_revoked(crl, revoked));

      auto rtmp = ASN1_ENUMERATED_new();
      ASN1_ENUMERATED_set(rtmp, REV_KEY_COMPROMISE);
      OSSL_CHECK(X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, rtmp, 0, 0));
      ASN1_ENUMERATED_free(rtmp);
      
      ASN1_INTEGER_free(serial);
    }
    OSSL_CHECK(X509_CRL_sort(crl));
    // Init context
    X509V3_CTX ctx;
    // setup context
    X509V3_set_ctx(&ctx, issuerCert, nullptr, nullptr, crl, 0);

    // setup db and db_meth, we need it for certificate policies
    X509V3_CONF_METHOD conf;
    openssl::Database db;
    conf.get_string = openssl::db_get_string;
    conf.get_section = openssl::db_get_section;
    conf.free_string = openssl::db_free_string;
    conf.free_section = openssl::db_free_section;
    ctx.db = &db;
    ctx.db_meth = &conf;

    for(auto extIt : CrlExtensions) {
        auto ext = X509V3_EXT_conf_nid(nullptr, &ctx, extIt.first,
                                       extIt.second.c_str());
        if(ext != nullptr) {
          OSSL_CHECK(X509_CRL_add_ext(crl, ext, -1));
        }
    }

    auto crlNumber = ASN1_INTEGER_new();
    ASN1_INTEGER_set(crlNumber, 1);
    OSSL_CHECK(X509_CRL_add1_ext_i2d(crl, NID_crl_number, crlNumber, 0, 0));
    ASN1_INTEGER_free(crlNumber);

    const EVP_MD *md = EVP_get_digestbynid(GetMDId(issuerKp));
    OSSL_CHECK(X509_CRL_sign(crl, issuerKp, md));

    ASN1_UTCTIME_free(asn1Tm);
    return std::move(X509CrlUptr(crl, ::X509_CRL_free));
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

  std::pair<X509Uptr, EvpPkeyUPtr> GenerateX509Certitificate(
      const AlgorithmEnum &algorithm, const ParamsSet &subject,
      const uint16_t ttlInDays,
      const std::vector<std::string> &crlDistributionPoints,
      std::vector<std::string> &ocspEndPoints,
      std::vector<std::string> &caEndPoints, X509 *issuer = nullptr,
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
      auto extensions = issuer == cert
                            ? std::map<int, std::string>(CaExtensions)
                            : std::map<int, std::string>(ClientExtensions);
      if (!crlDistributionPoints.empty()) {
        extensions.insert(
            {NID_crl_distribution_points,
             fmt::format("URI:{}", fmt::join(crlDistributionPoints, ","))});
      }

      // fill info access
      std::vector<std::string> info{2};
      if (!caEndPoints.empty()) {
        info[0] = fmt::format("caIssuers;URI:{}", fmt::join(caEndPoints, ","));
      }
      if (!ocspEndPoints.empty()) {
        info[1] = fmt::format("OCSP;URI:{}", fmt::join(ocspEndPoints, ","));
      }
      if (!caEndPoints.empty() || !ocspEndPoints.empty()) {
        extensions.insert(
            {NID_info_access, fmt::format("{}", fmt::join(info, ","))});
      }

      for (auto extIt : extensions) {
        auto ext = X509V3_EXT_conf_nid(nullptr, &ctx, extIt.first,
                                       extIt.second.c_str());
        if (ext != nullptr) {
          OSSL_CHECK(X509_add_ext(cert, ext, -1));
          X509_EXTENSION_free(ext);
        } else {
          LOG_WARNING("Failed to add cerificate extensions. NID: {}, "
                      "extensions: {}. Error: {}.",
                      extIt.first, extIt.second, openssl::get_errors_string());
        }
      }

      // fill info access
      //  AUTHORITY_INFO_ACCESS* info = X509_get_ext_d2i(cert, NID_info_access,
      //  nullptr, nullptr);

      // sign cert
      const EVP_MD *md = EVP_get_digestbynid(GetMDId(issuerKp));
      OSSL_CHECK(X509_sign(cert, issuerKp, md));

      return std::make_pair(std::move(X509Uptr(cert, ::X509_free)),
                            std::move(key));

    } catch (...) {
      throw std::runtime_error("GenerateX509Certitificate failed.");
    }
  }

  inline int GetMDId(EVP_PKEY *pkey) {
    auto pkey_nid = EVP_PKEY_base_id(pkey);
    auto md_nid = NID_undef;
    switch (pkey_nid) {
    case NID_id_GostR3410_2012_256:
      return NID_id_GostR3411_2012_256;
      break;
    case NID_id_GostR3410_2012_512:
      return NID_id_GostR3411_2012_512;
      break;
    }
    return md_nid;
  }

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
