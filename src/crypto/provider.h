#ifndef _CASERV_PROVIDER_H_
#define _CASERV_PROVIDER_H_

#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/md5.h>

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
