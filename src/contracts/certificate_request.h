#ifndef _CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_
#define _CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_

#include "enums.h"
#include <cstdint>
#include <string>
#include <vector>

namespace contracts {

    struct CertificateRequestBase {
        AlgorithmEnum algorithm{AlgorithmEnum::GostR3410_2012_256};
        std::string commonName;
        std::string country{"RU"};
        std::string localityName;
        std::string stateOrProvinceName;
        std::string streetAddress;
        std::string emailAddress;
        std::vector<KeyUsageEnum> KeyUsage;
        std::vector<ExtendedKeyUsageEnum> ExtendedKeyUsage;
        uint16_t ttlInDays{365};
    };

    struct PhysicalPersonCertificateRequest : public CertificateRequestBase {
        std::string inn;
        std::string snils;
        std::string givenName;
        std::string surname;
    };

    struct IndividualEntrepreneurCertificateRequest : public PhysicalPersonCertificateRequest {
        std::string ogrnip;
    };

    struct JuridicalPersonCertificateRequest : public PhysicalPersonCertificateRequest {
        std::string innLe;
        std::string ogrn;
        std::string organizationName;
        std::string organizationUnitName;
        std::string title;
    };

    typedef JuridicalPersonCertificateRequest CertificateRequest;

} // namespace contracts

#endif //_CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_