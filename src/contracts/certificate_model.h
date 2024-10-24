#ifndef _CASERV_CONTRACTS_CERTIFICATE_H_
#define _CASERV_CONTRACTS_CERTIFICATE_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "paged_response.h"


namespace contracts {

    struct CertificateModel {
        std::string_view serial;
        std::string_view thumbprint;
        std::string_view caSerial;
        std::string_view commonName;
        std::string_view issueDate;
        bool revoked;
        std::string_view revokeDate;
    };

    struct CertificateAuthorityModel {
        std::string_view serial;
        std::string_view thumbprint;
        std::string_view commonName;
        std::string_view issueDate;
        std::vector<uint8_t> certificate;
        std::vector<uint8_t> privateKey;
        std::string_view publicUrl;
    };
    
    using CertificateModels = PagedResponse<CertificateModel>;
    using CertificateAuthorityModels = PagedResponse<CertificateAuthorityModel>;
}

#endif //_CASERV_CONTRACTS_CERTIFICATE_H_