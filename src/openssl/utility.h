#ifndef _CASERV_OPENSSL_UTILITY_H_
#define _CASERV_OPENSSL_UTILITY_H_

#include "defines.h"
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <vector>

namespace openssl {

inline std::vector<std::uint8_t> get_certificate_data(X509* cert) {
    auto bio = BIO_new(BIO_s_mem());
    OSSL_CHECK(PEM_write_bio_X509(bio, cert));
    uint8_t* data;
    auto len = BIO_get_mem_data(bio, &data);
    auto result = std::vector<uint8_t>(data, data + len);
    OSSL_CHECK(BIO_free(bio));
    return result;
}

inline std::vector<std::uint8_t> get_private_key_data(EVP_PKEY* pkey){
    auto bio = BIO_new(BIO_s_mem());
    OSSL_CHECK(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, 0, nullptr));
    uint8_t* data;
    auto len = BIO_get_mem_data(bio, &data);
    auto result = std::vector<uint8_t>(data, data + len);
    OSSL_CHECK(BIO_free(bio));
    return result;
}

inline std::vector<std::uint8_t> get_public_key_data(EVP_PKEY* pkey){
    auto bio = BIO_new(BIO_s_mem());
    OSSL_CHECK(PEM_write_bio_PUBKEY(bio, pkey));
    uint8_t* data;
    auto len = BIO_get_mem_data(bio, &data);
    auto result = std::vector<uint8_t>(data, data + len);
    OSSL_CHECK(BIO_free(bio));
    return result;
}

};

#endif //_CASERV_OPENSSL_UTILITY_H_