#ifndef _CASERV_OPENSSL_UTILITY_H_
#define _CASERV_OPENSSL_UTILITY_H_

#include "defines.h"
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <string_view>
#include <vector>

namespace openssl {

/* 
    Convert X509 struct to bytearray
*/
inline std::vector<std::byte> get_certificate_data(X509 *cert) {
  auto bio = BIO_new(BIO_s_mem());
  OSSL_CHECK(PEM_write_bio_X509(bio, cert));
  std::byte *data;
  auto len = BIO_get_mem_data(bio, &data);
  auto result = std::vector<std::byte>(data, data + len);
  OSSL_CHECK(BIO_free(bio));
  return result;
}

/* 
    Convert byte array to X509 struct
*/
inline X509 *get_certificate(const std::vector<std::byte> &data) {
  auto bio = BIO_new_mem_buf(data.data(), data.size());
  auto result = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  OSSL_CHECK(BIO_free(bio));
  return result;
}

/* 
    Get private key as byte array from EVP_PKEY struct
*/
inline std::vector<std::byte> get_private_key_data(EVP_PKEY *pkey) {
  auto bio = BIO_new(BIO_s_mem());
  OSSL_CHECK(
      PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, 0, nullptr));
  std::byte *data;
  auto len = BIO_get_mem_data(bio, &data);
  auto result = std::vector<std::byte>(data, data + len);
  OSSL_CHECK(BIO_free(bio));
  return result;
}

/* 
    Get public key as byte array from EVP_PKEY struct
*/
inline std::vector<std::byte> get_public_key_data(EVP_PKEY *pkey) {
  auto bio = BIO_new(BIO_s_mem());
  OSSL_CHECK(PEM_write_bio_PUBKEY(bio, pkey));
  std::byte *data;
  auto len = BIO_get_mem_data(bio, &data);
  auto result = std::vector<std::byte>(data, data + len);
  OSSL_CHECK(BIO_free(bio));
  return result;
}

/* 
    Convert byte array to EVP_PKEY struct
*/
inline EVP_PKEY *get_private_key(const std::vector<std::byte> &privateKey) {
  auto skbio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(skbio, nullptr, nullptr, nullptr);
  OSSL_CHECK(BIO_free(skbio));
  return pkey;
}

/* 
    Convert X509_CRL to byte array
*/
inline std::vector<std::byte> get_crl_data(X509_CRL *crl) {
  auto bio = BIO_new(BIO_s_mem());
  OSSL_CHECK(PEM_write_bio_X509_CRL(bio, crl));
  std::byte *data;
  auto len = BIO_get_mem_data(bio, &data);
  auto result = std::vector<std::byte>(data, data + len);
  OSSL_CHECK(BIO_free(bio));
  return result;
}

/* 
    Create PKCS12 container
*/
inline std::vector<std::byte> create_pfx(EVP_PKEY *pkey, X509 *cert, X509 *ca,
                                         const char *name,
                                         const char *password = nullptr) {
  auto castack = sk_X509_new_null();
  if (ca != nullptr) {
    sk_X509_push(castack, ca);
  }
  auto pkcs =
      PKCS12_create(password, name, pkey, cert, castack, NID_id_Gost28147_89,
                    NID_id_Gost28147_89, 0, NID_gost_mac_12, 0);
  auto bio = BIO_new(BIO_s_mem());
  OSSL_CHECK(i2d_PKCS12_bio(bio, pkcs));
  std::byte *data;
  auto len = BIO_get_mem_data(bio, &data);
  auto result = std::vector<std::byte>(data, data + len);
  OSSL_CHECK(BIO_free(bio));
  PKCS12_free(pkcs);
  sk_X509_free(castack);
  return result;
}

/* 
    Create PKCS12 container file
*/
inline void create_pfx_file(const char *fileName, EVP_PKEY *pkey, X509 *cert,
                            X509 *ca, const char *name,
                            const char *password = nullptr) {
  auto castack = sk_X509_new_null();
  if (ca != nullptr) {
    sk_X509_push(castack, ca);
  }
  auto pkcs =
      PKCS12_create(password, name, pkey, cert, castack, NID_id_Gost28147_89,
                    NID_id_Gost28147_89, 0, NID_gost_mac_12, 0);
  auto file = fopen(fileName, "wb");
  i2d_PKCS12_fp(file, pkcs);
  fclose(file);
  PKCS12_free(pkcs);
  sk_X509_free(castack);
}

/* 
    Get message digest id by private key
*/
inline int GetMDId(EVP_PKEY *pKey) {
  auto pkeyNid = EVP_PKEY_base_id(pKey);
  auto mdNid = NID_undef;
  switch (pkeyNid) {
  case NID_id_GostR3410_2012_256:
    return NID_id_GostR3411_2012_256;
    break;
  case NID_id_GostR3410_2012_512:
    return NID_id_GostR3411_2012_512;
    break;
  }
  return mdNid;
}

/*
  Add subject entry
*/
inline void NameAddEntry(X509_NAME *name, const std::string_view field,
                         const std::string_view val, int type = MBSTRING_UTF8) {
  if (val.empty())
    return;
  OSSL_CHECK(X509_NAME_add_entry_by_txt(
      name, field.data(), type, (unsigned char *)val.data(), -1, -1, 0));
}

inline std::string get_serial_hex(X509* cert) {
  auto serial = X509_get_serialNumber(cert);
  auto bn = ASN1_INTEGER_to_BN(serial, nullptr);
  std::string  result(BN_bn2hex(bn));
  BN_free(bn);
  return result;
}

inline std::string get_serial_dec(X509* cert) {
  auto serial = X509_get_serialNumber(cert);
  auto bn = ASN1_INTEGER_to_BN(serial, nullptr);
  std::string  result(BN_bn2dec(bn));
  BN_free(bn);
  return result;
}

inline std::string get_thumbprint_SHA1(X509* cert) {
  unsigned char buf[20];
  unsigned int len = 0;
  size_t resultLen = 0;
  std::string result;
  result.reserve(40);
  const auto digest = EVP_sha1();
  OSSL_CHECK(X509_digest(cert, digest, buf, &len));
  if (OPENSSL_buf2hexstr_ex(nullptr, 0, &resultLen, buf, 20, 0) != 0)
  {
      result.resize(resultLen);
      OPENSSL_buf2hexstr_ex(&result[0], resultLen, &resultLen, buf, 20, 0);
  }
  return result;
}


inline char *db_get_string(void *db, const char *section, const char *value) {
  LOG_DEBUG("db_get_string. Params: section - {}, value - {}.", section, value);
  return nullptr;
}

inline STACK_OF(CONF_VALUE) * db_get_section(void *db, const char *section) {
  LOG_DEBUG("db_get_section. Parmas: section - {}.", section);
  return nullptr;
}

inline void db_free_string(void *db, char *str) { LOG_DEBUG("db_free_string"); }

inline void db_free_section(void *db, STACK_OF(CONF_VALUE)* section) { LOG_DEBUG("db_free_section"); }


}; // namespace openssl

#endif //_CASERV_OPENSSL_UTILITY_H_
