#ifndef _CASERV_CONTRACTS_GENERATED_CERTIFICATE_H_
#define _CASERV_CONTRACTS_GENERATED_CERTIFICATE_H_

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace contracts {

    struct PKCS12Container {
        std::vector<std::byte> container;
        std::string serialNumber;
        std::string thumbprint;
    };

    struct Certificate {
        std::vector<std::byte> privateKey;
        std::vector<std::byte> certificate;
        std::string serialNumber;
        std::string thumbprint;
    };

    struct Crl {
        std::vector<std::byte> content;
    };

    using PKCS12ContainerUPtr = std::unique_ptr<PKCS12Container>;
    using CertificateUPtr = std::unique_ptr<Certificate>;
    using CrlUPtr = std::unique_ptr<Crl>;

}

#endif //_CASERV_CONTRACTS_GENERATED_CERTIFICATE_H_