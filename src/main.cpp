// caserver.cpp : Defines the entry point for the application.
//

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <format>
#include <fstream>
#include <httpserver.hpp>
#include <ios>
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
#include <string_view>
#include <utility>
#include <vector>

#include "base/icrypto_provider.h"
#include "base/idatabase.h"
#include "contracts/certificate_model.h"
#include "contracts/certificate_request.h"
#include "contracts/enums.h"
#include "httpservice/get_certificate.h"
#include "httpservice/get_crt.h"
#include "openssl/crypto_provider.h"
#include "postgre/pgdatabase.h"
#include "service/caservice.h"
#include "httpservice/get_crl.h"

using namespace std;


contracts::JuridicalPersonCertificateRequest caReq;
contracts::JuridicalPersonCertificateRequest clientReq;

int main() {

  try {
    // OPENSSL_add_all_algorithms_conf();
    // OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
    spdlog::set_level(spdlog::level::level_enum::debug);
    // openssl::Provider provider{nullptr};
    openssl::OpensslCryptoProvider provider;

    contracts::JuridicalPersonCertificateRequest caReq;
    caReq.commonName = "ООО Очень Тестовый УЦ";
    caReq.country = "RU";
    caReq.stateOrProvinceName = "78 г.Санкт-Петербург";
    caReq.localityName = "Санкт-Петербург";
    caReq.streetAddress = "ул. Большая Морская";
    caReq.emailAddress = "test@testemail.ru";
    caReq.innLe = "1234567890";
    caReq.ogrn = "1234567890123";
    caReq.organizationName = "ООО Очень Тестовый УЦ";
    caReq.organizationUnitName = "Отдел фейковых выдач";
    caReq.algorithm = contracts::AlgorithmEnum::GostR3410_2012_512;

    contracts::JuridicalPersonCertificateRequest clientReq;
    clientReq.commonName = "ООО Рога и Копыта";
    clientReq.country = "RU";
    clientReq.stateOrProvinceName = "78 г.Санкт-Петербург";
    clientReq.localityName = "Санкт-Петербург";
    clientReq.streetAddress = "ул. Пушкина";
    clientReq.emailAddress = "test@testemail.ru";
    clientReq.inn = "123456789012";
    clientReq.givenName = "Иван Иванович";
    clientReq.surname = "Иванов";
    clientReq.snils = "12334536322";
    clientReq.innLe = "2234467890";
    clientReq.ogrn = "2224567890123";
    clientReq.organizationName = "ООО Рога и Копыта";
    clientReq.organizationUnitName = "Директорат";
    clientReq.title = "Предводитель";
    clientReq.algorithm = contracts::AlgorithmEnum::GostR3410_2012_256;

    std::vector<std::string_view> crlDistributionPoints {
      "http://test.ru/crl.crl"
    };

    std::vector<std::string_view> ocspEndPoints {
    };

    std::vector<std::string_view> caEndPoints {
      "http://test.ru/root.crt"
    };


    // auto root = provider.GeneratedCACertificate(caReq);

    // contracts::CaInfo caInfo {
    //   .crlDistributionPoints = crlDistributionPoints,
    //   .ocspEndPoints = ocspEndPoints,
    //   .caEndPoints = caEndPoints,
    //   .privateKey = root->privateKey,
    //   .certificate = root->certificate
    // };

    // auto client = provider.GenerateClientCertitificate(clientReq, caInfo);
    // LOG_INFO(client->serialNumber.data());
    // LOG_INFO(client->thumbprint);

    // auto client = provider.GenerateClientCertitificate(clientReq, issuerCert, issuerKey);
    // print(client);
    // auto crl = provider.CreateCRL(issuerCert, issuerKey, std::vector<X509*>{client.first.get()});

    // postrgre::PgDatabase db(connString);

    contracts::CreateCertificateAuthorityModel createCaModel;
    createCaModel.request = caReq;
    createCaModel.publicUrl = "http://testca";


    auto connString = "postgresql://admin:admin@127.0.0.1:5432/postgres";
    base::IDataBasePtr db = std::make_shared<postgre::PgDatabase>(connString);
    base::ICryptoProviderUPtr crypt = std::make_unique<openssl::OpensslCryptoProvider>();
    auto caService = std::make_shared<serivce::CaService>(db, std::move(crypt));

    // auto res = caService->InvalidateCrl("D8B3F0B524C07A2E6BFD533EF6C23F52");

    // auto client = caService->CreateClientCertificate("D8B3F0B524C07A2E6BFD533EF6C23F52", clientReq);
    // std::ofstream file;
    // file.open("test.pfx", std::ios::out | std::ios::binary);
    // file.write(reinterpret_cast<const char*>(client->container.data()), client->container.size());
    // file.close();

    httpserver::webserver ws = httpserver::create_webserver(8080);
    httpservice::GetCrlEndpoint getCrl(caService);
    httpservice::GetCrtEndpoint getCrt(caService);
    httpservice::GetCertificateEndpoint getCertificate(caService);
    ws.register_resource(getCrl.Route(), &getCrl);
    ws.register_resource(getCrt.Route(), &getCrt);
    ws.register_resource(getCertificate.Route(), &getCertificate);
    ws.start(true);

 } catch (std::exception &ex) {
    cout << ex.what() << endl;
  }
  return 0;
}
