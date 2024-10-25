#ifndef _CASERV_OPENSSL_CONFIG_DB_H_
#define _CASERV_OPENSSL_CONFIG_DB_H_

#include <openssl/safestack.h>

#include "defines.h"

namespace openssl {


// stub openssl conf.
class ConfigDatabase {
public:
  ConfigDatabase() = default;
  ~ConfigDatabase() = default;
};


} // namespace openssl

#endif //_CASERV_OPENSSL_CONFIG_DB_H_
