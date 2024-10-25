#ifndef _CASERV_BASE_DATABASE_H_
#define _CASERV_BASE_DATABASE_H_

#include <memory>
#include <string>
#include <vector>

#include "./../common/appsettings.h"
#include "./../contracts/certificate_model.h"

namespace base {

using namespace contracts;

class IDataBase {
public:
  virtual ~IDataBase() = default;
  virtual CertificateModelPtr GetCertificate(const std::string &serial) = 0;
  virtual std::vector<CertificateModelPtr>
  GetCertificates(const std::string &caSerial) = 0;
  virtual std::vector<CertificateModelPtr> GetAllCertificates() = 0;
  virtual CertificateAuthorityModelPtr GetCa(const std::string &serial) = 0;
  virtual std::vector<CertificateAuthorityModelPtr> GetAllCa() = 0;

  virtual void AddCertificate(const CertificateModel &cert) = 0;
  virtual void AddCA(const CertificateAuthorityModel &ca) = 0;

  virtual void MakeCertificateRevoked(const std::string &serial,
                                      const std::string &revokeDate) = 0;
  virtual std::vector<CertificateModelPtr>
  GetRevokedList(const std::string &caSerial) = 0;
};

using IDataBasePtr = std::shared_ptr<IDataBase>();

} // namespace base

#endif //_CASERV_BASE_DATABASE_H_
