#ifndef _CASERV_PROVIDER_H_
#define _CASERV_PROVIDER_H_

#include <memory>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <memory.h>

#ifndef EVP_PKEY_CTRL_GOST_PARAMSET
# define EVP_PKEY_CTRL_GOST_PARAMSET (EVP_PKEY_ALG_CTRL+1)
#endif // !EVP_PKEY_CTRL_GOST_PARAMSET

#define OSSL_CHECK(x, ctx)                                              \
    do                                                                  \
    {                                                                   \
        int osslResult = x;                                             \
        if(x <= 0)                                                      \
        {                                                               \
            std::cout << "OPENSSL error: " << osslResult << std::endl;  \
            ERR_print_errors_fp(stderr);                                \
            if(ctx != nullptr) EVP_PKEY_CTX_free(ctx);                  \
            abort();                                                    \
        }                                                               \
    } while(0)                                                          \


class Provider
{
public:
	Provider(ENGINE* pEngine);
	~Provider() = default;

	EVP_PKEY* GenerateKeyPair();
	X509* GenerateX509Certitificate(EVP_PKEY* key, const EVP_MD* md);
private:
	ENGINE* _engine{nullptr};
};

#endif // !_CASERV_PROVIDER_H_
