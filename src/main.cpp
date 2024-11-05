// caserver.cpp : Defines the entry point for the application.
//

#include <cstdio>
#include <cstring>
#include <ctime>
#include <httpserver.hpp>
#include <iostream>
#include <memory>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/txt_db.h>
#include <ostream>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/icrypto_provider.h"
#include "common/appsettings.h"
#include "common/logger.h"
#include "contracts/certificate_request.h"
#include "contracts/enums.h"
#include "http/get_ca.h"
#include "http/get_ca_certificate.h"
#include "http/get_certificate.h"
#include "http/get_certificates.h"
#include "http/get_crl.h"
#include "http/get_crt.h"
#include "http/post_create_ca.h"
#include "http/post_issue_certificate.h"
#include "openssl/crypto_provider.h"
#include "postgre/pgdatabase.h"
#include "service/caservice.h"

using namespace std;

contracts::JuridicalPersonCertificateRequest caReq;
contracts::JuridicalPersonCertificateRequest clientReq;

void logInfo(const std::string &e) { LOG_INFO("HTTP request: {}", e); }
void logError(const std::string &e) { LOG_ERROR("HTTP error: {}", e); };

int main() {

  try {
    // OPENSSL_add_all_algorithms_conf();
    // OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
    spdlog::set_level(spdlog::level::level_enum::debug);
    openssl::OpensslCryptoProvider provider;
    AppSettings settings;

    auto connString = settings.GetParam("CASERV_PGDB", "postgresql://admin:admin@127.0.0.1:5432/postgres");
    db::IDataBasePtr db = std::make_shared<postgre::PgDatabase>(connString);
    base::ICryptoProviderUPtr crypt =
        std::make_unique<openssl::OpensslCryptoProvider>();
    auto caService = std::make_shared<serivce::CaService>(db, std::move(crypt));
    // caService->CreateCA(createCaModel);

    // auto client = caService->CreateClientCertificate(
    //     "E5767690E57697D703D8F3F21F047FC2", clientReq);
    // std::ofstream file;
    // file.open("test.pfx", std::ios::out | std::ios::binary);
    // file.write(reinterpret_cast<const char*>(client->container.data()),
    // client->container.size()); file.close();

    httpserver::webserver ws =
        httpserver::create_webserver(8080)
        .log_access(logInfo)
        .log_error(logError);
        
    http::GetCrlEndpoint getCrl(caService);
    http::GetCrtEndpoint getCrt(caService);
    http::GetCertificateEndpoint getCertificate(caService);
    http::GetCertificatesEndpoint getCertificates(caService);
    http::GetCaEndpoint getCa(caService);
    http::GetCaCertificateEndpoint getCaCert(caService);
    http::IssueCertificateEndpoint issueCert(caService);
    http::CreateCaEndpoint createCa(caService);
    getCrl.Register(ws);
    getCrt.Register(ws);
    getCertificate.Register(ws);
    getCertificates.Register(ws);
    getCa.Register(ws);
    getCaCert.Register(ws);
    issueCert.Register(ws);
    createCa.Register(ws);

    LOG_INFO("Server started.")
    ws.start(true);

  } catch (std::exception &ex) {
    cout << ex.what() << endl;
  }
  return 0;
}
