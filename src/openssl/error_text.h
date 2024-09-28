#ifndef _CASERV_OPENSSL_ERROR_TEXT_H_
#define _CASERV_OPENSSL_ERROR_TEXT_H_

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string>

namespace openssl 
{
    inline std::string get_errors_string()
    {
        BIO* pBio = BIO_new(BIO_s_mem());
        ERR_print_errors(pBio);
        char* pData = nullptr;
        auto len = BIO_get_mem_data(pBio, &pData);
        std::string result(pData, len);
        BIO_free(pBio);
        return result;
    }
}


#endif //_CASERV_OPENSSL_ERROR_TEXT_H_
