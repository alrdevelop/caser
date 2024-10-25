#ifndef _CASERV_CONTRACTS_CA_INFO_H_
#define _CASERV_CONTRACTS_CA_INFO_H_

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>
namespace contracts {

struct CaInfo {
  std::vector<std::string_view> crlDistributionPoints;
  std::vector<std::string_view> ocspEndPoints;
  std::vector<std::string_view> caEndPoints;
  std::vector<std::byte> privateKey;
  std::vector<std::byte> certificate;
};

using CaInfoUPtr = std::unique_ptr<CaInfo>;

} // namespace contracts

#endif //_CASERV_CONTRACTS_CA_INFO_H_