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

char *db_get_string(void *db, const char *section, const char *value) {
  LOG_DEBUG("db_get_string. Params: section - {}, value - {}.", section, value);
  return nullptr;
}
STACK_OF(CONF_VALUE) * db_get_section(void *db, const char *section) {
  LOG_DEBUG("db_get_section. Parmas: section - {}.", section);
  return nullptr;
}

void db_free_string(void *db, char *str) { LOG_DEBUG("db_free_string"); }

void db_free_section(void *db, STACK_OF(CONF_VALUE)* section) { LOG_DEBUG("db_free_section"); }

} // namespace openssl

#endif //_CASERV_OPENSSL_DB_H_
