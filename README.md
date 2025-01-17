# caserv

## Configuration
You must create database and provide connection string to environment variable:
- PostgreSQL: CASERV_PGDB

Example (defaulValue):
```
postgresql://admin:admin@127.0.0.1:5432/postgres
```
### Database scripts
PostgreSQL:
```

CREATE TABLE IF NOT EXISTS public.ca (
	"serial" varchar(250) NOT NULL,
	"thumbprint" varchar(250) NOT NULL,
	"commonName" varchar(500) NOT NULL,
	"issueDate" timestamp with time zone NOT NULL,
	"certificate" bytea NOT NULL,
	"privateKey" bytea NOT NULL,
	"publicUrl" varchar(500) NOT NULL,
	CONSTRAINT ca_serial_pk PRIMARY KEY ("serial"),
	CONSTRAINT ca_unique_thumbprint UNIQUE ("thumbprint")
);
CREATE TABLE IF NOT EXISTS public.certificates (
	"serial" varchar(250) NOT NULL,
	"thumbprint" varchar(250) NOT NULL,
	"caSerial" varchar(250) NOT NULL,
	"commonName" varchar(500) NOT NULL,
	"issueDate" timestamp with time zone NOT NULL,
	"revokeDate" timestamp with time zone NULL,
	CONSTRAINT certificates_pk PRIMARY KEY ("serial"),
	CONSTRAINT certificates_unique_thumbprint UNIQUE ("thumbprint"),
	CONSTRAINT certificates_ca_fk FOREIGN KEY ("caSerial") REFERENCES public.ca("serial")
);

CREATE TABLE IF NOT EXISTS public.crl (
	"caSerial" varchar(250) NOT NULL,
	"number" integer NOT NULL,
	"issueDate" timestamp with time zone NOT NULL,
	"expireDate" timestamp with time zone NOT NULL,
	"lastSerial" varchar(250) NULL,
	"content" bytea NOT NULL,
	CONSTRAINT crl_pk PRIMARY KEY ("caSerial","number")
);

```


## Enums
algorithmEnum:
- 0 - GOST2012_256
- 1 - GOST2012_512

subjectTypeEnum:
- 0 - Physical person
- 1 - Individual entrepreneur
- 2 - Juridical person

## API

### HTTP GET ca/{caSerial}/certificate
- caSerial - CA serial number.
Returns CA certificate file.

### HTTP GET ca/{caSerial}
- caSerial - CA certificate serial number.
Returns CA data model.
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
- serial - Certificate serial number.
Returns certificate data model.
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
- serial - Certificate serial number.
Returns certificates data model array.
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
- crlFile - CRL file name (***template: {crlSerial}.crl***).
Returns CRL file.
This endpoint used in certificate distribution points.

### HTTP GET crt/{crtFile}
- crtFile - CA certificate file name (***template: {crtSerial}.crt***).
Returns CA certificate file.
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

PublicUrl used for certficate distribution points (CRL, CRT access). You CSP must have access to this URL. URL must be in next format http://example.com do not use back slash at end of URL (http://example.com/).

Example:

СURL request:
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
СURL request:
```
curl -X POST http://localhost:8080/ca/D8B3F0B524C07A2E6BFD533EF6C23F52/issue/ -H 'Content-Type: application/json' -d '{ "commonName" : "ООО Рога и Копыта", "country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург", "localityName" : "Санкт-Петербург",  "streetAddress" : "ул. Пушкина", "emailAddress" : "test@testemail.ru", "inn" : "123456789012", "givenName" : "Иван Иванович", "surname" : "Иванов", "snils" : "12334536322", "innLe" : "2234467890", "ogrn" : "2224567890123", "organizationName" : "ООО Рога и Копыта", "organizationUnitName" : "Директорат", "title" : "Предводитель", "algorithm" : 0, "subjectType" : 2, "ttlInDays" : 365, "pin" : "you_secret_pin_for_pfx"}' --output test.pfx
```

Subject type 0:
```
{
  "subjectType" : 0
  "algorithm" : 0
  "ttlInDays" : 365
  "country" : "RU",
  "localityName" : "Saint Petersburg",
  "stateOrProvinceName" : "78 Saint Petersburg",
  "streetAddress" : "Bolshaya Morskaya",
  "emailAddress" : "mail@mail",
  "inn" : "123456789012",
  "snils" : "12334536322",
  "givenName" : "Ivan Ivanovich",
  "surname" : "Ivanov",
  "pin" : "you_secret_pin_for_pfx"
}
```
Subject type 1:
```
{
  "subjectType" : 1
  "algorithm" : 0
  "ttlInDays" : 365
  "country" : "RU",
  "localityName" : "Saint Petersburg",
  "stateOrProvinceName" : "78 Saint Petersburg",
  "streetAddress" : "Bolshaya Morskaya",
  "emailAddress" : "mail@mail",
  "inn" : "123456789012",
  "snils" : "12334536322",
  "givenName" : "Ivan Ivanovich",
  "surname" : "Ivanov",
  "ogrnip" : "2224567890123",
  "organizationName" : "IP Ivanov Inan Ivanovich",
  "pin" : "you_secret_pin_for_pfx"
}
```
Subject type 2:
```
{
  "subjectType" : 2,
  "algorithm" : 0,
  "ttlInDays" : 365,
  "country" : "RU",
  "localityName" : "Saint Petersburg",
  "stateOrProvinceName" : "78 Saint Petersburg",
  "streetAddress" : "Bolshaya Morskaya",
  "emailAddress" : "mail@mail",
  "inn" : "123456789012",
  "snils" : "12334536322",
  "givenName" : "Ivan Ivanovich",
  "surname" : "Ivanov",
  "innLe" : "1234567890",
  "ogrn" : "2224567890123",
  "organizationName" : "OOO Roga i kopita",
  "organizationUnitName" : "",
  "title" : "CEO",
  "pin" : "you_secret_pin_for_pfx"
}
```

### HTTP POST certificate/revoke/

Revoke client certificicate.
Input model:
```
{
  serial : string
}
```

