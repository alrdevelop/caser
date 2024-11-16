#ifndef _CASERV_SERVICE_CASERVICE_H_
#define _CASERV_SERVICE_CASERVICE_H_

#include "./../base/icrypto_provider.h"
#include "./../db/idatabase.h"
#include "models/models.h"
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace serivce {

using namespace base;
using namespace service::models;
using namespace db::models;
using namespace db;
class CaService {
public:
  CaService(IDataBasePtr db, ICryptoProviderUPtr crypto);
  ~CaService();

  StoredCertificateModelPtr GetCertificate(const std::string &serial);
  std::vector<StoredCertificateModelPtr> GetCertificates(const std::string &caSerial);
  std::vector<StoredCertificateModelPtr> GetAllCertificates();
  StoredCertificateAuthorityModelPtr GetCa(const std::string &serial);
  std::vector<std::byte> GetCaCertificateData(const std::string &serial);
  std::vector<StoredCertificateAuthorityModelPtr> GetAllCa();
  std::vector<std::byte> GetCrl(const std::string &caSerial);
  std::vector<std::byte> InvalidateCrl(const std::string &caSerial);

  StoredCertificateAuthorityModelPtr CreateCA(const CreateCertificateAuthorityModel& model);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const IssueCertificateModel& model);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const JuridicalPersonCertificateRequest& req);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const IndividualEntrepreneurCertificateRequest& req);
  PKCS12ContainerUPtr CreateClientCertificate(const std::string_view& caSerial, const PhysicalPersonCertificateRequest& req);

  void RevokeCertificate(const RevokeCertificateModel& model);

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