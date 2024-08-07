#include "provider.h"

#ifndef EVP_PKEY_CTRL_GOST_PARAMSET
# define EVP_PKEY_CTRL_GOST_PARAMSET (EVP_PKEY_ALG_CTRL+1)
#endif // !EVP_PKEY_CTRL_GOST_PARAMSET


Provider::Provider(ENGINE* pEngine) : _engine(pEngine)
{
}

EVP_PKEY* Provider::GenerateKeyPair()
{
    EVP_PKEY* result;
    EVP_PKEY_CTX* pkeyCtx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2012_256, _engine);

    EVP_PKEY_paramgen_init(pkeyCtx);

    EVP_PKEY_CTX_ctrl(pkeyCtx, NID_id_GostR3410_2012_256, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_GOST_PARAMSET, NID_id_tc26_gost_3410_2012_256_paramSetA, NULL);

    if (EVP_PKEY_keygen_init(pkeyCtx) <= 0 && EVP_PKEY_keygen(pkeyCtx, &result) <= 0)
    {
        if (pkeyCtx)
        {
            EVP_PKEY_CTX_free(pkeyCtx);
        }
    }
    return result;
}

X509* Provider::GenerateX509Certitificate(EVP_PKEY* key, EVP_MD* md)
{
    auto cert = X509_new();
    // set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // set dates
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    // set public key
    X509_set_pubkey(cert, key);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME* name = X509_get_subject_name(cert);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(cert, name);

    if (!X509_sign(cert, key, md))
    {
        X509_free(cert);
        return nullptr;
    }
    return cert;
}
