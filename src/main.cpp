// caserver.cpp : Defines the entry point for the application.
//

#include <iostream>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "crypto/provider.h"

using namespace std;



int main()
{

	try 
	{
		OPENSSL_add_all_algorithms_conf();
		ENGINE* engine = ENGINE_by_id("gost");
		Provider provider{ engine };
		auto kp = provider.GenerateKeyPair();


		const EVP_MD* md = EVP_get_digestbyname(SN_id_GostR3411_2012_256);
		auto cert = provider.GenerateX509Certitificate(kp, md);
		// if (cert != nullptr)
		// {

		// }
		auto file = fopen("test.cer", "wb");
		OSSL_CHECK(PEM_write_X509(file, cert), nullptr);
		fclose(file);
		cout << "Hello CMake." << endl;
	}
	catch (std::exception& ex)
	{
		cout << ex.what() << endl;
	}
	return 0;
}
