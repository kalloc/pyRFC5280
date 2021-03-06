# -*- coding:utf-8 -*-
#
id_ce = '2.5.29.'
id_pkix = '1.3.6.1.5.5.7.'
id_pe = id_pkix + '1.'
id_qt = id_pkix + '2.'
id_kp = id_pkix + '3.'

OID = {
    #algo
    '1.2.840.113549.1.1.1' : ('rsaEncryption' , 'RSA (PKCS #1 v1.5) key transport algorithm'),
    '1.2.840.113549.1.1.5' : ('sha1withRSAEncryption', 'sha1withRSAEncryption'),
    '1.3.14.3.2.29' : ('sha1WithRSA', 'SHA1 with RSA signature (obsolete)'),
    '1.2.643.2.2.19' :  ('GostR3410-2001', 'Ключ подписи ГОСТ-34.10-2001'),
    '1.2.643.2.2.9' :  ('GOST R 34.11-94 (Russian hash algorithm)', 'Хэш ГОСТ-34.11-94'),
    '1.2.643.2.2.3' :  ('GostR3411-94-with-GostR3410-2001', 'Подпись ГОСТ-34.10-2001 - Алгоритм Хэша + Алгоритм Ключа'),
    '1.2.643.2.2.30.0' : ('GostR3411_94_TestParamSet', 'Тестовый узел замены'),
    '1.2.643.2.2.30.1' : ('GostR3411_94_CryptoProParamSet', 'Узел замены функции хэширования по умолчанию, вариант \'Верба-О\''),
    '1.2.643.2.2.30.2' : ('GostR3411_94_CryptoPro_B_ParamSet', 'Узел замены функции хэширования, вариант 1'),
    '1.2.643.2.2.30.3' : ('GostR3411_94_CryptoPro_C_ParamSet', 'Узел замены функции хэширования, вариант 2'),
    '1.2.643.2.2.30.4' : ('GostR3411_94_CryptoPro_D_ParamSet', 'Узел замены функции хэширования, вариант 3'),
    '1.2.643.2.2.31.0' : ('Gost28147_89_TestParamSet', 'Тестовый узел замены алгоритма шифрования'),
    '1.2.643.2.2.31.1' : ('Gost28147_89_CryptoPro_A_ParamSet', 'Узел замены алгоритма шифрования по умолчанию, вариант \'Верба-О\''),
    '1.2.643.2.2.31.2' : ('Gost28147_89_CryptoPro_B_ParamSet', 'Узел замены алгоритма шифрования,вариант 1'),
    '1.2.643.2.2.31.3' : ('Gost28147_89_CryptoPro_C_ParamSet', 'Узел замены алгоритма шифрования,вариант 2'),
    '1.2.643.2.2.31.4' : ('Gost28147_89_CryptoPro_D_ParamSet', 'Узел замены алгоритма шифрования,вариант 3'),
    '1.2.643.2.2.31.5' : ('Gost28147_89_CryptoPro_Oscar_1_1_ParamSet', 'Узел замены, вариант карты КриптоРИК'),
    '1.2.643.2.2.31.6' : ('Gost28147_89_CryptoPro_Oscar_1_0_ParamSet', 'Узел замены, используемый при шифровании с хэшированием'),
    '1.2.643.2.2.32.2' : ('GostR3410_94_CryptoPro_A_ParamSet', 'Параметры P,Q,A цифровой подписи ГОСТ Р 34.10-94, вариант \'Верба-О\'. Могут использоваться также в алгоритме Диффи-Хеллмана'),
    '1.2.643.2.2.32.3' : ('GostR3410_94_CryptoPro_B_ParamSet', 'Параметры P,Q,A цифровой подписи ГОСТ Р 34.10-94, вариант 1. Могут использоваться также в алгоритме Диффи-Хеллмана'),
    '1.2.643.2.2.32.4' : ('GostR3410_94_CryptoPro_C_ParamSet', 'Параметры P,Q,A цифровой подписи ГОСТ Р 34.10-94, вариант 2. Могут использоваться также в алгоритме Диффи-Хеллмана'),
    '1.2.643.2.2.32.5' : ('GostR3410_94_CryptoPro_D_ParamSet', 'Параметры P,Q,A цифровой подписи ГОСТ Р 34.10-94, вариант 3. Могут использоваться также 2 алгоритме Диффи-Хеллмана'),
    '1.2.643.2.2.33.1' : ('GostR3410_94_CryptoPro_XchA_ParamSet', 'Параметры P,Q,A алгоритма Диффи-Хеллмана на базе экспоненциальной функции, вариант 1'),
    '1.2.643.2.2.33.2' : ('GostR3410_94_CryptoPro_XchB_ParamSet', 'Параметры P,Q,A алгоритма Диффи-Хеллмана на базе экспоненциальной функции, вариант 2'),
    '1.2.643.2.2.33.3' : ('GostR3410_94_CryptoPro_XchC_ParamSet', 'Параметры P,Q,A алгоритма Диффи-Хеллмана на базе экспоненциальной функции, вариант 3'),
    '1.2.643.2.2.35.0' : ('GostR3410_2001_TestParamSet', 'Тестовые параметры a, b, p,q, (x,y) алгоритма ГОСТ Р 34.10-2001'),
    '1.2.643.2.2.35.1' : ('GostR3410_2001_CryptoPro_A_ParamSet', 'Параметры a, b, p,q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант криптопровайдера'),
    '1.2.643.2.2.35.2' : ('GostR3410_2001_CryptoPro_B_ParamSet', 'Параметры a, b, p,q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант карты КриптоРИК'),
    '1.2.643.2.2.35.2' : ('GostR3410_2001_CryptoPro_C_ParamSet', 'Параметры a, b, p,q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант 1'),
    '1.2.643.2.2.36.0' : ('GostR3410_2001_CryptoPro_XchA_ParamSet', 'Параметры a, b, p,q, (x,y) алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант криптопровайдера. Используются те же параметры, что и с идентификатором szOID_GostR3410_2001_CryptoPro_A_ParamSet'),
    '1.2.643.2.2.35.3' : ('GostR3410_2001_CryptoPro_XchB_ParamSet', 'Параметры a, b, p,q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант 1'),
    '1.2.840.10040.4.3' : ('dsaWithSha1', 'dsaWithSha1'),
    '1.2.840.10040.4.1' : ('dsa', 'dsa'),

    #other
    '2.5.4.10' : ('organizationName', 'Organization name'),
    '2.5.4.11' : ('organizationUnitName', 'Organization unit name'),
    '2.5.4.3' : ('commonName', 'commonName'),
    '2.5.4.6' : ('countryName', 'countryName'),
    '1.2.840.113549.1.9.8' : ('unstructuredAddress', 'unstructuredAddress'),
    '2.5.4.43' : ('initials', 'initials'),
    '2.5.4.42' : ('givenName', 'givenName'),
    '2.5.4.7' : ('localityName', 'localityName'),
    '2.5.4.8' : ('MO', 'MO'),
    '2.5.4.9' : ('streetAddress', 'streetAddress'),
    '2.5.4.12' : ('title', 'title'), 
    '1.2.840.113549.1.9.2' :  ('UnstructuredName', 'UnstructuredName'),
    '1.2.840.113549.1.9.1' : ('Email', 'Email'),
    '2.5.4.4' :  ('surname', 'surname'),
    id_ce + '32' : ('certificatePolicies', 'certificatePolicies'),
    id_qt + '1' : ('id-qt-cps', 'CPS'),
    id_qt + '2' : ('id-qt-unotice', 'User Notice'),
    id_ce + '17' : ('subjectAltName', 'Alternative Subject Name'),
    id_ce + '18' : ('issuerAltName', 'Issuer Subject Name'),
    id_ce + '9' : ('subjectDirectoryAttributes' , 'Subject Directory Attributes'),
    id_ce + '30' : ('nameConstraints', 'Name Constraints'),
    id_ce + '36' : ('policyConstraints', 'Policy Constraints'),
    '0.9.2342.19200300.100.1.25' : ( 'domainComponent', 'domainComponent'),
    '2.16.840.1.113730.1.1' : ('nsCertType', 'Netscape Cert Type'),
    '2.5.29.37' : ('extKeyUsage', 'X509v3 Extended Key Usage'),
    '2.5.29.15' : ('keyUsage', 'X509v3 Key Usage'),
    '2.5.29.19' : ('basicConstraints', 'X509v3 Basic Constraints'),
    '2.5.29.23' : ('instructionCode', 'Hold instruction code.'),
    '2.5.29.33' : ('policyMappings', 'Policy mappings'),
    '2.5.29.14' : ('subjectKeyIdentifier', 'Subject key identifier'),
    '2.5.29.35' : ('authorityKeyIdentifier', 'Authority key identifier'),
    id_kp + '2' : ('clientAuth', 'Indicates that a certificate can be used as an SSL client certificate'),
    id_kp + '1' : ('serverAuth', 'TLS WWW server authentication'),
    id_kp + '3' : ('codeSigning', 'Signing of downloadable executable code'),
    id_kp + '4' : ('emailProtection', 'Email protection'),
    id_kp + '8' : ('timeStamping', 'Binding the hash of an object to a time'),
    id_kp + '9' : ('OCSPSigning', 'Signing OCSP responses'),
    id_ce + '31' : ('cRLDistributionPoints', 'CRL Distribution Points'),
    id_ce + '54' : ('inhibitAnyPolicy', 'Inhibit AnyPolicy'),
    id_ce + '46' : ('freshestCRL', 'Freshest CRL'),
    id_pe + '1' : ('authorityInfoAccess', 'Authority Information Access'),
    id_pkix + '48.2' : ('caIssuers', 'caIssuers'),
    id_pkix + '48.1' : ('ocsp', 'OCSP'),
    id_pkix + '48.11' : ('subjectInfoAccess', 'subjectInfoAccess'),
    id_pkix + '48.5' : ('caRepository', 'caRepository'),
    id_pkix + '48.3' : ('timeStamping', 'timeStamping'),
    id_ce + '20' : ('cRLNumber', 'cRLNumber'),
    id_ce + '27' : ('deltaCRLIndicator', 'deltaCRLIndicator'),
    id_ce + '28' : ('issuingDistributionPoint', 'issuingDistributionPoint'),
    id_ce + '21' : ('cRLReasons', 'cRLReasons'),
    id_ce + '24' : ('invalidityDate', 'invalidityDate'),
    id_ce + '29' : ('certificateIssuer', 'certificateIssuer'),
    id_ce + '16' : ('privateKeyUsagePeriod', 'privateKeyUsagePeriod'),
    id_ce + '37.0' : ('anyExtendedKeyUsage', 'anyExtendedKeyUsage'),
    id_ce + '23' : ('holdInstructionCode', 'holdInstructionCode'),
    '2.2.840.10040.2' : ('holdInstruction', 'holdInstruction'),
    '2.2.840.10040.2.1' : ('holdinstruction-none', 'holdinstruction-none'),
    '2.2.840.10040.2.2' : ('oldinstruction-callissuer', 'oldinstruction-callissuer'),
    '2.2.840.10040.2.3' : ('holdinstruction-reject', 'holdinstruction-reject')
}
