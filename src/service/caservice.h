#ifndef _CASERV_SERVICE_CASERVICE_H_
#define _CASERV_SERVICE_CASERVICE_H_

#include "./../base/icrypto_provider.h"
#include "./../base/idatabase.h"
#include <memory>
#include <string>
#include <string_view>

namespace serivce {

using namespace base;

class CaService {
public:
  CaService(IDataBasePtr db, ICryptoProviderUPtr crypto);
  ~CaService();

  CertificateModelPtr GetCertificate(const std::string &serial);
  std::vector<CertificateModelPtr> GetCertificates(const std::string &caSerial);
  std::vector<CertificateModelPtr> GetAllCertificates();
  StoredCertificateAuthorityModelPtr GetCa(const std::string &serial);
  std::vector<StoredCertificateAuthorityModelPtr> GetAllCa();

  StoredCertificateAuthorityModelPtr CreateCA(const CreateCertificateAuthorityModel& model);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const JuridicalPersonCertificateRequest& req);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const IndividualEntrepreneurCertificateRequest& req);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const PhysicalPersonCertificateRequest& req);

private:
  CaInfo GetCaInfo(const std::string_view& caSerial);
  void SaveClientCertificate(const std::string_view& caSerial, const std::string_view& commonName, const PKCS12ContainerUPtr& container);
private:
  IDataBasePtr _db;
  ICryptoProviderUPtr _crypto;
};

using CaServicePtr = std::shared_ptr<CaService>;

} // namespace serivce

#endif //_CASERV_SERVICE_CASERVICE_H_