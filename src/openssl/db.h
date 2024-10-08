#ifndef _CASERV_OPENSSL_DB_H_
#define _CASERV_OPENSSL_DB_H_

#include <openssl/safestack.h>

#include "defines.h"

namespace openssl {


class Database {
public:
  Database() = default;
  ~Database() = default;
};

char *DbGetString(void *db, const char *section, const char *value) {
  LOG_INFO("DbGetString");
  return nullptr;
}
STACK_OF(CONF_VALUE) * DbGetSection(void *db, const char *section) {
  LOG_INFO("DbGetSection");
  return nullptr;
}

void DbFreeString(void *db, char *str) { LOG_INFO("DbFreeString"); }

void DbFreeSection(void *db, STACK_OF(CONF_VALUE)* section) { LOG_INFO("DbFreeSection"); }

} // namespace openssl

#endif //_CASERV_OPENSSL_DB_H_
