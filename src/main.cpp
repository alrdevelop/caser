// caserver.cpp : Defines the entry point for the application.
//

#include "contracts/enums.h"
#include "openssl/provider.h"
#include <iostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>

using namespace std;

int main() {

  try {
    OPENSSL_add_all_algorithms_conf();
    // OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
    openssl::Provider provider{nullptr};
    auto kp = provider.GenerateKeyPair(contracts::GostR3410_2012_256);
    auto cert =  provider.GenerateX509Certitificate({ .inn = "123456789012", .givenName = "Иван Иванович", .surName = "Иванов"});

    // const EVP_MD* md = EVP_get_digestbyname(SN_id_GostR3411_2012_256);
    // auto cert = provider.GenerateX509Certitificate(kp, md);
    // if (cert != nullptr)
    // {

    // }
    // auto file = fopen("test.cer", "wb");
    // OSSL_CHECK(PEM_write_X509(file, cert), nullptr);
    // fclose(file);
    cout << "Hello CMake." << endl;

  } catch (std::exception &ex) {
    cout << ex.what() << endl;
  }
  return 0;
}
