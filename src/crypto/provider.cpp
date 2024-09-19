#include "provider.h"
#include <iostream>
#include <memory>
#include <vector>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>


Provider::Provider(ENGINE* pEngine) : _engine(pEngine)
{
}

EVP_PKEY* Provider::GenerateKeyPair()
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2012_256, _engine);
    OSSL_CHECK(EVP_PKEY_paramgen_init(ctx), ctx);
    OSSL_CHECK(EVP_PKEY_CTX_ctrl(ctx, NID_id_GostR3410_2012_256, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_GOST_PARAMSET, NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet, NULL), ctx);
    OSSL_CHECK(EVP_PKEY_paramgen_init(ctx), ctx);
    OSSL_CHECK(EVP_PKEY_keygen_init(ctx), ctx);
    OSSL_CHECK(EVP_PKEY_keygen(ctx, &pkey), ctx);
    return pkey;
}


X509* Provider::GenerateX509Certitificate(EVP_PKEY* key, const EVP_MD* md)
{
    auto cert = X509_new();

    // set serial number
    //ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // try to calc SHA-1 for X509_pubkey_digest()
    ASN1_STRING* serialNumber = X509_get_serialNumber(cert);
    std::vector<uint8_t> serial(20);
    RAND_bytes(serial.data(), 20);
    ASN1_STRING_set(serialNumber, serial.data(), 20);


    // 0x00 - v1, 0x01 - v2, 0x02 - v3
    X509_set_version(cert, 0x02);
    // set dates
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    // set public key
    X509_set_pubkey(cert, key);

    //
    unsigned int len = 0;
    X509_pubkey_digest(cert, md, serial.data(), &len);



    /* We want to copy the subject name to the issuer name. */
    X509_NAME* name = X509_get_subject_name(cert);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

    /* Now set the issuer name. */
    // OSSL_CHECK(X509_set_issuer_name(cert, name), nullptr);

    // OSSL_CHECK(X509_sign(cert, key, md), nullptr);
    // if (X509_sign(cert, key, md) <= 0)
    // {
    //     ERR_print_errors_fp(stderr);
    //     X509_free(cert);
    //     return nullptr;
    // }
    return cert;
}
