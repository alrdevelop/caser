# caserv

## Configuration
Setup ENV CASERV_PGDB
Example (defaulValue):
```
postgresql://admin:admin@127.0.0.1:5432/postgres
```

## Enums
algorithmEnum:
- 0 - GOST2012_256
- 1 - GOST2012_512

subjectTypeEnum:
- 0 - ФЛ
- 1 - ИП
- 2 - ЮЛ

## API

### HTTP GET ca/{caSerial}/certificate
- caSerial - CA serial number
Return CA certificate file in BER encoding.

### HTTP GET ca/{caSerial}
- caSerial - CA certificate serial number
Return CA data model.
```
{
  serial : string
  thumbprint : string
  caSerial : string
  commonName : string
  issueDate : datetime
}

```
### HTTP GET certificate/{serial}
- serial - Certificate serial number
Return certificate data model.
```
{
  serial : string
  thumbprint : string
  caSerial : string
  commonName : string
  issueDate : datetime
  revokeDate : datetime
}

```
### HTTP GET certificates/{serial}
- serial - Certificate serial number
Return certificates data model array.
```
{[{
  serial : string
  thumbprint : string
  caSerial : string
  commonName : string
  issueDate : datetime
  revokeDate : datetime
},..]}

```

### HTTP GET crl/{crlFile}
- crlFile - CRL file name (***template: {crlSerial}.crl***)
Return CRL file.
This endpoint used in certificate distribution points.

### HTTP GET crt/{crtFile}
- crtFile - CA certificate file name (***template: {crtSerial}.crl***)
Return CA certificate file.
This endpoint used in certificate distribution points.

### HTTP POST ca/create/
Create CA certificicate.
Input model:
```
{
  algorithm : algorithmEnum
  country : string
  localityName : string
  stateOrProvinceName : string
  streetAddress : string
  emailAddress : string
  innLe : string
  ogrn : string
  organizationName : string
  ttlInDays : int
  publicUrl : string

}
```
Example:
```
curl -X POST http://localhost:8080/ca/create/ -H 'Content-Type: application/json' -d  '{"country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург", "localityName" : "Санкт-Петербург", "streetAddress" : "ул. Большая Морская", "emailAddress" : "test@testemail.ru", "innLe" : "1234567890", "ogrn" : "1234567890123", "organizationName" : "ООО Очень Тестовый УЦ", "publicUrl" : "http://localhost:8080", "algorithm" : 1, "ttlInDays" : 3650}'
```


### HTTP POST ca/{caSerial}/issue/
Issue client certificicate.
- caSerial - CA certificate serial number
Input model:
```
{
  subjectType : subjectTypeEnum
  algorithm : algorithmEnum
  ttlInDays : int
  country : string
  localityName : string
  stateOrProvinceName : string
  streetAddress : string
  emailAddress : string
  inn : string
  snils : string
  givenName : string
  surname : string
  ogrnip : string
  innLe : string
  ogrn : string
  organizationName : string
  organizationUnitName : string
  title : string
  pin : string
}
```
If success, returns PKCS12 container file

Example:
```
curl -X POST http://localhost:8080/ca/D8B3F0B524C07A2E6BFD533EF6C23F52/issue/ -H 'Content-Type: application/json' -d '{ "commonName" : "ООО Рога и Копыта", "country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург", "localityName" : "Санкт-Петербург",  "streetAddress" : "ул. Пушкина", "emailAddress" : "test@testemail.ru", "inn" : "123456789012", "givenName" : "Иван Иванович", "surname" : "Иванов", "snils" : "12334536322", "innLe" : "2234467890", "ogrn" : "2224567890123", "organizationName" : "ООО Рога и Копыта", "organizationUnitName" : "Директорат", "title" : "Предводитель", "algorithm" : 0, "subjectType" : 2, "ttlInDays" : 365}' --output test.pfx
```

