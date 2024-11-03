#ifndef _CASERV_CONTRACTS_ENUMS_H_
#define _CASERV_CONTRACTS_ENUMS_H_

namespace contracts 
{
    enum class AlgorithmEnum
    {
        GostR3410_2012_256 = 0,
        GostR3410_2012_512
    };

    enum class KeyUsageEnum
    {
        Critical = 0,
        DigitalSignature,
        KeyEncipherment,
        NonRepudiation,
        DataEncipherment,
        KeyAgreement,
        KeyCertSign,
        cRLSign,
        EncipherOnly,
        DecipherOnly,
    };

    enum class ExtendedKeyUsageEnum
    {
        Critical = 0,
        ServerAuth,
        ClientAuth,
        CodeSigning,
        EmailProtection,
        TimeStamping,
        OCSPSigning,
    };

    enum class SujectTypeEnum {
        PhysicalPerson = 0,
        IndividualEntrepreneur = 1,
        JuridicalPerson = 2,
    };
}

#endif //_CASERV_CONTRACTS_ENUMS_H_