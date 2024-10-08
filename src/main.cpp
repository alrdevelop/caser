// caserver.cpp : Defines the entry point for the application.
//

#include "contracts/certificate_request.h"
#include "contracts/enums.h"
#include "openssl/provider.h"
#include "openssl/utility.h"
#include <cstdint>
#include <cstring>
#include <iostream>
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
    cout << v;
  }
  for(auto v : openssl::get_public_key_data(data.second.get())) {
    cout << v;
  }
  for(auto v : openssl::get_certificate_data(data.first.get())) {
    cout << v;
  }
}

int main() {

  try {
    // OPENSSL_add_all_algorithms_conf();
    // OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
    spdlog::set_level(spdlog::level::level_enum::debug);
    openssl::Provider provider{nullptr};

    contracts::JuridicalPersonCertificateRequest req;
    req.commonName = "Иванов Иван Иванович";
    req.country = "RU";
    req.stateOrProvinceName = "78 г.Санкт-Петербург";
    req.localityName = "Санкт-Петербург";
    req.streetAddress = "ул. Большая Морская";
    req.emailAddress = "test@testemail.ru";
    req.KeyUsage = {contracts::KeyUsageEnum::Critical,
                    contracts::KeyUsageEnum::DigitalSignature};
    req.ExtendedKeyUsage = {contracts::ExtendedKeyUsageEnum::Critical,
                            contracts::ExtendedKeyUsageEnum::ClientAuth,
                            contracts::ExtendedKeyUsageEnum::EmailProtection};

    req.inn = "123456789012";
    req.givenName = "Иван Иванович";
    req.surname = "Иванов";
    req.snils = "12334536322";

    req.innLe = "1234567890";
    req.organizationName = "ООО Рога и Копыта";
    req.organizationUnitName = "Директорат";
    req.title = "Предводитель";

    auto rootCert = provider.GenerateX509Certitificate((contracts::CertificateRequest)req);
    auto client = provider.GenerateX509Certitificate(req, rootCert.first.get(), rootCert.second.get());
    //print(rootCert);
    //print(client);
    for(auto v : openssl::create_pfx(client.second.get(), client.first.get(), "test", "123")){
      cout << v;
    }

  } catch (std::exception &ex) {
    cout << ex.what() << endl;
  }
  return 0;
}
