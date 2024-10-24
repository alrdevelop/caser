// caserver.cpp : Defines the entry point for the application.
//

#include "contracts/certificate_model.h"
#include "contracts/certificate_request.h"
#include "contracts/enums.h"
#include "openssl/provider.h"
#include "openssl/utility.h"
#include "postgre/pgdatabase.h"
#include <cstdint>
#include <cstring>
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
#include <utility>
#include <vector>

using namespace std;


void print(const std::pair<openssl::X509Uptr, openssl::EvpPkeyUPtr>& data) {
  for(auto v : openssl::get_private_key_data(data.second.get())) {
    cout << (unsigned char)v;
  }
  for(auto v : openssl::get_public_key_data(data.second.get())) {
    cout << (unsigned char)v;
  }
  for(auto v : openssl::get_certificate_data(data.first.get())) {
    cout << (unsigned char)v;
  }
}

contracts::JuridicalPersonCertificateRequest caReq;
contracts::JuridicalPersonCertificateRequest clientReq;

int main() {

  try {
    // OPENSSL_add_all_algorithms_conf();
    // OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
    spdlog::set_level(spdlog::level::level_enum::debug);
    openssl::Provider provider{nullptr};

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
    caReq.ogrn = "2224567890123";
    clientReq.organizationName = "ООО Рога и Копыта";
    clientReq.organizationUnitName = "Директорат";
    clientReq.title = "Предводитель";
    clientReq.algorithm = contracts::AlgorithmEnum::GostR3410_2012_256;


    auto rootCert = provider.GenerateCa(caReq);
    // //print(rootCert);

    auto rootPkData = openssl::get_private_key_data(rootCert.second.get());
    auto rootCertData = openssl::get_certificate_data(rootCert.first.get());
    // auto issuerKey = openssl::get_private_key(rootPkData);
    // auto issuerCert = openssl::get_certificate(rootCertData);

    // auto client = provider.GenerateClientCertitificate(clientReq, issuerCert, issuerKey);
    // print(client);
    // auto crl = provider.CreateCRL(issuerCert, issuerKey, std::vector<X509*>{client.first.get()});

    auto connString = "postgresql://admin:admin@127.0.0.1:5432/postgres";
    postrgre::PgDatabase db(connString);

    contracts::CertificateAuthorityModel caModel;
    caModel.commonName = caReq.commonName;
    caModel.serial = "1221";
    caModel.thumbprint = "1";
    caModel.certificate = rootCertData;
    caModel.privateKey = rootPkData;
    caModel.issueDate = "2024-12-12";

    // db.AddCA(caModel);

    for(auto ca : db.GetAllCa()) {
      auto a = ca;
      for(auto c : a->certificate) {
        cout << (unsigned char)c;
      }
    }

  } catch (std::exception &ex) {
    cout << ex.what() << endl;
  }
  return 0;
}
