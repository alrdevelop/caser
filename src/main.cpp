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
#include <vector>

using namespace std;

int main() {

  try {
    OPENSSL_add_all_algorithms_conf();
    // OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
    openssl::Provider provider{nullptr};
    auto kp = provider.GenerateKeyPair(contracts::AlgorithmEnum::GostR3410_2012_256);

	contracts::JuridicalPersonCertificateRequest req;
	req.commonName = "Иванов Иван Иванович";
	req.country = "RU";
	req.stateOrProvinceName = "78 г.Санкт-Петербург";
	req.localityName = "Санкт-Петербург";
	req.streetAddress = "ул. Большая Морская";
	req.emailAddress = "test@testemail.ru";
	req.KeyUsage = {contracts::KeyUsageEnum::Critical, contracts::KeyUsageEnum::DigitalSignature};
	req.ExtendedKeyUsage = {contracts::ExtendedKeyUsageEnum::Critical, contracts::ExtendedKeyUsageEnum::ClientAuth, contracts::ExtendedKeyUsageEnum::EmailProtection};

	req.inn = "123456789012";
	req.givenName = "Иван Иванович";
	req.surname = "Иванов";
	req.snils = "12334536322";

  req.innLe = "1234567890";
  req.organizationName = "ООО Рога и Копыта";
  req.organizationUnitName = "Директорат";
  req.title = "Предводитель";


  auto cert =  provider.GenerateX509Certitificate((contracts::CertificateRequest)req);

    // const EVP_MD* md = EVP_get_digestbyname(SN_id_GostR3411_2012_256);
    // auto cert = provider.GenerateX509Certitificate(kp, md);
    // if (cert != nullptr)
    // {

    // }
    // auto file = fopen("test.cer", "wb");
    // OSSL_CHECK(PEM_write_X509(file, cert), nullptr);
    // fclose(file);
	auto result = openssl::get_certificate_data(cert.get());
	for(auto it : result)
	{
		cout << it;
	}
  } catch (std::exception &ex) {
    cout << ex.what() << endl;
  }
  return 0;
}
