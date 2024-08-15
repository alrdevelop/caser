// caserver.cpp : Defines the entry point for the application.
//

#include "caserver.h"
#include "crypto/provider.h"

using namespace std;

void PrintCertData(X509* cert)
{
	BIO* b64;
	PEM_write_bio_X509(b64, cert);
	BUF_MEM* bptr;
	BIO_get_mem_ptr(b64, &bptr);
	BUF_MEM_free(bptr);
	BIO_free(b64);
}

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
		if (cert != nullptr)
		{

		}
		auto file = fopen("test.cer", "wb");
		PEM_write_X509(file, cert);
		fclose(file);
		cout << "Hello CMake." << endl;
	}
	catch (std::exception& ex)
	{
		cout << ex.what() << endl;
	}
	return 0;
}
