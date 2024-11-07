# caserv

## Configuration
Setup ENV CASERV_PGDB
Example (defaulValue):
```
postgresql://admin:admin@127.0.0.1:5432/postgres
```

## Enums
algorithm:
- 0 - GOST2012_256
- 1 - GOST2012_512

subjectType:
- 0 - ФЛ
- 1 - ИП
- 2 - ЮЛ

## API

### HTTP GET ca/{caSerial}/certificate
- caSerial - CA serial number
Return CA certificate file in BER encoding.

### HTTP GET ca/{caSerial}
- caSerial - CA serial number
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


## CURL requests

CA:
```
curl -X POST http://localhost:8080/ca/create/ -H 'Content-Type: application/json' -d  '{"country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург", "localityName" : "Санкт-Петербург", "streetAddress" : "ул. Большая Морская", "emailAddress" : "test@testemail.ru", "innLe" : "1234567890", "ogrn" : "1234567890123", "organizationName" : "ООО Очень Тестовый УЦ", "publicUrl" : "http://localhost:8080", "algorithm" : 1, "ttlInDays" : 3650}'
```

Client:
```
curl -X POST http://localhost:8080/ca/D8B3F0B524C07A2E6BFD533EF6C23F52/issue/ -H 'Content-Type: application/json' -d '{ "commonName" : "ООО Рога и Копыта", "country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург", "localityName" : "Санкт-Петербург",  "streetAddress" : "ул. Пушкина", "emailAddress" : "test@testemail.ru", "inn" : "123456789012", "givenName" : "Иван Иванович", "surname" : "Иванов", "snils" : "12334536322", "innLe" : "2234467890", "ogrn" : "2224567890123", "organizationName" : "ООО Рога и Копыта", "organizationUnitName" : "Директорат", "title" : "Предводитель", "algorithm" : 0, "subjectType" : 2, "ttlInDays" : 365}' --output test.pfx
```