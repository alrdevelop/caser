# caserv

# Enums
algorithm:
0 - GOST2012_256
1 - GOST2012_512

subjectType:
0 - ФЛ
1 - ИП
2 - ЮЛ

# CURL requests

CA:
   "commonName": "ООО Очень Тестовый УЦ", "country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург";
    caReq.localityName = "Санкт-Петербург";
    caReq.streetAddress = "ул. Большая Морская";
    caReq.emailAddress = "test@testemail.ru";
    caReq.innLe = "1234567890";
    caReq.ogrn = "1234567890123";
    caReq.organizationName = "ООО Очень Тестовый УЦ";
    caReq.organizationUnitName = "Отдел фейковых выдач";
    caReq.algorithm = contracts::AlgorithmEnum::GostR3410_2012_512;


Client:
curl -X POST http://localhost:8080/ca/D8B3F0B524C07A2E6BFD533EF6C23F52/issue/ -H 'Content-Type: application/json' -d '{ "commonName" : "ООО Рога и Копыта", "country" : "RU", "stateOrProvinceName" : "78 г.Санкт-Петербург", "localityName" : "Санкт-Петербург",  "streetAddress" : "ул. Пушкина", "emailAddress" : "test@testemail.ru", "inn" : "123456789012", "givenName" : "Иван Иванович", "surname" : "Иванов", "snils" : "12334536322", "innLe" : "2234467890", "ogrn" : "2224567890123", "organizationName" : "ООО Рога и Копыта", "organizationUnitName" : "Директорат", "title" : "Предводитель", "algorithm" : 1, "subjectType" : 2, "ttlInDays" : 356}' --output test.pfx
