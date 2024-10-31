#ifndef _CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_
#define _CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_

#include "enums.h"
#include "./../common/datetime.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace contracts {
using namespace datetime;
    struct CertificateRequestBase {
        AlgorithmEnum algorithm{AlgorithmEnum::GostR3410_2012_256};
        std::string_view commonName;
        std::string_view country{"RU"};
        std::string_view localityName;
        std::string_view stateOrProvinceName;
        std::string_view streetAddress;
        std::string_view emailAddress;
        uint16_t ttlInDays{365};
    };

    struct PhysicalPersonCertificateRequest : public CertificateRequestBase {
        std::string_view inn;
        std::string_view snils;
        std::string_view givenName;
        std::string_view surname;
    };

    struct IndividualEntrepreneurCertificateRequest : public PhysicalPersonCertificateRequest {
        std::string_view ogrnip;
    };

    struct JuridicalPersonCertificateRequest : public PhysicalPersonCertificateRequest {
        std::string_view innLe;
        std::string_view ogrn;
        std::string_view organizationName;
        std::string_view organizationUnitName;
        std::string_view title;
    };

    typedef JuridicalPersonCertificateRequest CertificateRequest;

    struct CrlEntry {
        std::string_view serialNumber;
        DateTimePtr revokationDate;
    };

    struct CrlRequest {
        long number;
        std::vector<CrlEntry> entries;
    };

} // namespace contracts

#endif //_CASERV_CONTRACTS_CERTIFICATE_REQUEST_H_