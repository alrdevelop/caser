#ifndef _CASERV_CONTRACTS_CERTIFICATE_H_
#define _CASERV_CONTRACTS_CERTIFICATE_H_

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "certificate_request.h"
#include "paged_response.h"


namespace contracts {

    struct CertificateModel {
        std::string_view serial;
        std::string_view thumbprint;
        std::string_view caSerial;
        std::string_view commonName;
        std::string_view issueDate;
        std::string_view revokeDate;
    };

    struct CertificateAuthorityModel {
        std::string_view serial;
        std::string_view thumbprint;
        std::string_view commonName;
        std::string_view issueDate;
        std::vector<std::byte> certificate;
        std::vector<std::byte> privateKey;
        std::string_view publicUrl;
    };

    struct CrlModel {
        std::string_view caSerial;
        long number;
        std::string_view issueDate;
        std::string_view lastSerial;
        std::vector<std::byte> content;
    };

    using CertificateModelPtr = std::shared_ptr<CertificateModel>;
    using CertificateAuthorityModelPtr = std::shared_ptr<CertificateAuthorityModel>;
    using CrlModelPtr = std::shared_ptr<CrlModel>;

    using CertificateModels = PagedResponse<CertificateModelPtr>;
    using CertificateAuthorityModels = PagedResponse<CertificateAuthorityModelPtr>;
    using CrlModels = PagedResponse<CrlModelPtr>;




    //TODO: separate db models and service requests/responses
    struct CreateCertificateAuthorityModel {
        JuridicalPersonCertificateRequest request;
        std::string_view publicUrl;
    };
    struct StoredCertificateAuthorityModel {
        std::string_view serial;
        std::string_view thumbprint;
        std::string_view commonName;
        std::string_view issueDate;
        std::string_view publicUrl;
        std::vector<std::byte> certificate;
    };
    

    using CreateCertificateAuthorityModelPtr = std::shared_ptr<CreateCertificateAuthorityModel>;
    using StoredCertificateAuthorityModelPtr = std::shared_ptr<StoredCertificateAuthorityModel>;
}

#endif //_CASERV_CONTRACTS_CERTIFICATE_H_