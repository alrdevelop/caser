#include "crypto_provider.h"
#include "config_db.h"
#include "defines.h"
#include "subject_builder.h"
#include "utils.h"
#include <algorithm>
#include <memory>
#include <string_view>

using namespace openssl;

static _::PhysicalPersonCertificateSubjectBuilder PhysicalPersonSubjectBuilder;
static _::IndividualEntrepreneurCertificateSubjectBuilder
    IndividualEntrepreneurSubjectBuilder;
static _::JuridicalPersonCertificateSubjectBuilder
    JuridicalPersonSubjectBuilder;

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
    {NID_basic_constraints, "CA:TRUE,pathlen:0"},
    {NID_key_usage, "critical,cRLSign,digitalSignature,keyCertSign"},
    {NID_certificate_policies,
     "1.2.643.100.113.1,1.2.643.100.113.2,anyPolicy"}};

static std::map<int, std::string> ClientExtensions{
    {NID_subject_key_identifier, "hash"},
    {NID_authority_key_identifier, "keyid,issuer"},
    {NID_key_usage, "critical, digitalSignature"},
    {NID_ext_key_usage, "clientAuth,"
                        "emailProtection,"
                        "1.2.643.2.2.34.6,"
                        "1.2.643.3.88.3.6,"
                        "1.2.643.3.88.1.1.1.7,"
                        "1.2.643.3.88.1.1.1.9,"
                        "1.2.643.3.88.1.1.1.10,"
                        "1.2.643.3.88.1.1.1.11"}};

OpensslCryptoProvider::OpensslCryptoProvider() {}

OpensslCryptoProvider::~OpensslCryptoProvider() {}

PKCS12ContainerUPtr OpensslCryptoProvider::GenerateClientCertitificate(
    const PhysicalPersonCertificateRequest &req, const CaInfo &caInfo) {
  auto subject = PhysicalPersonSubjectBuilder.SubjectName(req);
  auto cert =
      GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays, &caInfo);
  auto result = new PKCS12Container{
      .container = openssl::create_pfx(
          openssl::get_private_key(cert->privateKey),
          openssl::get_certificate(cert->certificate),
          openssl::get_certificate(caInfo.certificate), nullptr),
      .serialNumber = cert->serialNumber,
      .thumbprint = cert->thumbprint};
    return std::move(PKCS12ContainerUPtr(result));  
}

PKCS12ContainerUPtr OpensslCryptoProvider::GenerateClientCertitificate(
    const IndividualEntrepreneurCertificateRequest &req, const CaInfo &caInfo) {
  auto subject = IndividualEntrepreneurSubjectBuilder.SubjectName(req);
  auto cert =
      GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays, &caInfo);
  auto result = new PKCS12Container{
      .container = openssl::create_pfx(
          openssl::get_private_key(cert->privateKey),
          openssl::get_certificate(cert->certificate),
          openssl::get_certificate(caInfo.certificate), nullptr),
      .serialNumber = cert->serialNumber,
      .thumbprint = cert->thumbprint};
    return std::move(PKCS12ContainerUPtr(result));  
}

PKCS12ContainerUPtr OpensslCryptoProvider::GenerateClientCertitificate(
    const JuridicalPersonCertificateRequest &req, const CaInfo &caInfo) {
  auto subject = JuridicalPersonSubjectBuilder.SubjectName(req);
  auto cert =
      GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays, &caInfo);
  auto result = new PKCS12Container{
      .container = openssl::create_pfx(
          openssl::get_private_key(cert->privateKey),
          openssl::get_certificate(cert->certificate),
          openssl::get_certificate(caInfo.certificate), nullptr),
      .serialNumber = cert->serialNumber,
      .thumbprint = cert->thumbprint};
    return std::move(PKCS12ContainerUPtr(result));  
}

CertificateUPtr OpensslCryptoProvider::GeneratedCACertificate(
    const JuridicalPersonCertificateRequest &req) {
  auto subject = JuridicalPersonSubjectBuilder.SubjectName(req);
  return GenerateX509Certitificate(req.algorithm, subject, req.ttlInDays, nullptr);
}

OpensslCryptoProvider::EvpPkeyUPtr
OpensslCryptoProvider::GenerateKeyPair(const PkeyParams &params) {
  EVP_PKEY *pkey{EVP_PKEY_new()};
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(params.keytype, nullptr);
  if (ctx == nullptr) {
    LOG_ERROR("EVP_PKEY_CTX_new_id fail. {}", openssl::get_errors_string());
    throw std::runtime_error("EVP_PKEY_CTX_new_id fail.");
  }

  try {
    OSSL_CHECK(EVP_PKEY_paramgen_init(ctx));
    OSSL_CHECK(EVP_PKEY_CTX_ctrl(ctx, params.keytype, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_GOST_PARAMSET, params.p1, NULL));
    OSSL_CHECK(EVP_PKEY_paramgen_init(ctx));
    OSSL_CHECK(EVP_PKEY_keygen_init(ctx));
    OSSL_CHECK(EVP_PKEY_keygen(ctx, &pkey));
    return std::move(EvpPkeyUPtr(pkey, ::EVP_PKEY_free));
  } catch (...) {
    if (ctx != nullptr) {
      EVP_PKEY_CTX_free(ctx);
    }
    throw std::runtime_error("GenerateKeyPair error.");
  }
}

CertificateUPtr OpensslCryptoProvider::GenerateX509Certitificate(
    const AlgorithmEnum &algorithm,
    const std::vector<std::pair<std::string_view, std::string_view>> &subject,
    const long &ttlInDays, const CaInfo *caInfo) {

  EVP_PKEY *issuerKp = nullptr;
  X509 *issuerCert = nullptr;

  if (caInfo != nullptr) {
    issuerKp = openssl::get_private_key(caInfo->privateKey);
    if (issuerKp == nullptr)
      throw errors::CryptoProviderError("CA private key not set.");
    issuerCert = openssl::get_certificate(caInfo->certificate);
    if (issuerCert == nullptr)
      throw errors::CryptoProviderError("CA certificate not set.");
  }

  try {
    auto pkeyParamsIt = PkeyOptions.find(algorithm);
    if (pkeyParamsIt == PkeyOptions.end()) {
      LOG_ERROR("Unsupported algorithm {}.", (int)algorithm);
      throw errors::CryptoProviderError("Unsupported AlgorithmEnum.");
    }

    auto params = pkeyParamsIt->second;
    auto key = GenerateKeyPair(params);

    if (caInfo == nullptr)
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
      NameAddEntry(name, subjPair.first.data(), subjPair.second.data());
    }

    // set public key
    OSSL_CHECK(X509_set_pubkey(cert, key.get()));

    // set issuer
    // if issuer is null, create self signed cert
    if (issuerCert == nullptr)
      issuerCert = cert;
    auto issuerName = X509_get_subject_name(issuerCert);
    OSSL_CHECK(X509_set_issuer_name(cert, issuerName));

    // Init context
    X509V3_CTX ctx;
    // setup context
    X509V3_set_ctx(&ctx, issuerCert, cert, nullptr, nullptr, 0);

    // setup db and db_meth, we need it for certificate policies
    X509V3_CONF_METHOD conf;
    conf.get_string = openssl::db_get_string;
    conf.get_section = openssl::db_get_section;
    conf.free_string = openssl::db_free_string;
    conf.free_section = openssl::db_free_section;
    ConfigDatabase db;
    ctx.db = &db;
    ctx.db_meth = &conf;

    // setup extensions
    auto extensions = caInfo == nullptr
                          ? std::map<int, std::string>(CaExtensions)
                          : std::map<int, std::string>(ClientExtensions);
    if (caInfo != nullptr) {
      if (!caInfo->crlDistributionPoints.empty()) {
        extensions.insert(
            {NID_crl_distribution_points,
             fmt::format("URI:{}",
                         fmt::join(caInfo->crlDistributionPoints, ","))});
      }

      // fill info access
      std::vector<std::string> info;
      if (!caInfo->caEndPoints.empty()) {
        info.push_back(fmt::format("caIssuers;URI:{}",
                                   fmt::join(caInfo->caEndPoints, ",")));
      }
      if (!caInfo->ocspEndPoints.empty()) {
        info.push_back(
            fmt::format("OCSP;URI:{}", fmt::join(caInfo->ocspEndPoints, ",")));
      }
      if (!info.empty()) {
        extensions.insert(
            {NID_info_access, fmt::format("{}", fmt::join(info, ","))});
      }
    }

    for (auto extIt : extensions) {
      auto ext =
          X509V3_EXT_conf_nid(nullptr, &ctx, extIt.first, extIt.second.c_str());
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
    const EVP_MD *md = EVP_get_digestbynid(openssl::GetMDId(issuerKp));
    OSSL_CHECK(X509_sign(cert, issuerKp, md));
    auto thumbprint = openssl::get_thumbprint_SHA1(cert);
    auto serialHex = openssl::get_serial_hex(cert);
    
    auto result = new Certificate();
    result->certificate = openssl::get_certificate_data(cert);
    result->privateKey = openssl::get_private_key_data(key.get());
    result->serialNumber = serialHex;
    result->thumbprint = thumbprint;
    return std::move(CertificateUPtr(result));

  } catch (...) {
  }
}
