#ifndef _CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_
#define _CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_

#include "enums.h"
#include <cstdint>
#include <string>
#include <vector>

namespace contracts {

    struct CertificateRequest {
        AlgorithmEnum algorithm{AlgorithmEnum::GostR3410_2012_256};
        std::string commonName;
        std::string country{"RU"};
        std::string stateOfProvinceName;
        std::string localityName;
        std::string streetAddress;
        std::string emailAddress;
        std::vector<KeyUsageEnum> KeyUsage;
        std::vector<ExtendedKeyUsageEnum> ExtendedKeyUsage;
        uint16_t ttlInDays{365};
    };

    struct PhysicalPersonCertificateRequest : public CertificateRequest {
        std::string inn;
        std::string snils;
        std::string givenName;
        std::string surName;
    };

} // namespace contracts

#endif //_CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_