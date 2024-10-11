#ifndef _CASERV_OPENSSL_UTILITY_H_
#define _CASERV_OPENSSL_UTILITY_H_

#include "defines.h"
#include <cstdint>
#include <cstdio>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
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

inline X509* get_certificate(const std::vector<uint8_t>& data) {
    auto bio = BIO_new_mem_buf(data.data(), data.size());
    auto result = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
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

inline EVP_PKEY* get_private_key(std::vector<uint8_t>& privateKey) {
    auto skbio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(skbio, nullptr, nullptr, nullptr);
    OSSL_CHECK(BIO_free(skbio));
    return pkey;
}

inline std::vector<std::uint8_t> create_pfx(EVP_PKEY* pkey, X509* cert, X509* ca, const char* name, const char* password = nullptr) {
    auto castack = sk_X509_new_null();
    if(ca != nullptr) {
        sk_X509_push(castack, ca);
    }
    auto pkcs = PKCS12_create(password, name, pkey, cert, castack, NID_id_Gost28147_89, NID_id_Gost28147_89, 0, NID_gost_mac_12, 0);
    auto bio = BIO_new(BIO_s_mem());
    OSSL_CHECK(i2d_PKCS12_bio(bio, pkcs));
    uint8_t* data;
    auto len = BIO_get_mem_data(bio, &data);
    auto result = std::vector<uint8_t>(data, data + len);
    OSSL_CHECK(BIO_free(bio));
    PKCS12_free(pkcs);
    sk_X509_free(castack);
    return result;
}

inline void create_pfx_file(const char* fileName, EVP_PKEY* pkey, X509* cert, X509* ca, const char* name, const char* password = nullptr) {
    auto castack = sk_X509_new_null();
    if(ca != nullptr) {
        sk_X509_push(castack, ca);
    }
    auto pkcs = PKCS12_create(password, name, pkey, cert, castack, NID_id_Gost28147_89, NID_id_Gost28147_89, 0, NID_gost_mac_12, 0);
    auto file = fopen(fileName, "wb");
    i2d_PKCS12_fp(file, pkcs);
    fclose(file);
    PKCS12_free(pkcs);
    sk_X509_free(castack);
}

};

#endif //_CASERV_OPENSSL_UTILITY_H_
