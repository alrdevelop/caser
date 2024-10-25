#ifndef _CASERV_OPENSSL_DEFINES_H_
#define _CASERV_OPENSSL_DEFINES_H_

#include "../common/logger.h"
#include "./../base/errors.h"
#include "error_text.h"

#define OSSL_CHECK(x)                                                           \
    do                                                                          \
    {                                                                           \
        int result = x;                                                         \
        if(result <= 0)                                                         \
        {                                                                       \
            LOG_ERROR("OpenSSL call error: {}", openssl::get_errors_string());  \
            throw base::errors::CryptoProviderError("OpenSSL call error.");     \
        }                                                                       \
    } while(0)                                                                  \


#ifndef EVP_PKEY_CTRL_GOST_PARAMSET
# define EVP_PKEY_CTRL_GOST_PARAMSET (EVP_PKEY_ALG_CTRL+1)
#endif // !EVP_PKEY_CTRL_GOST_PARAMSET


#endif // _CASERV_OPENSSL_DEFINES_H_