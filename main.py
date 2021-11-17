#################################################
# Desenvolvedores: Mateus Patz, Carlos Munhos,  #
# Eduardo Thomazi, Thiago Araujo Pereira        #
#                                               #
# Trabalho acadêmico da disciplina de           #
# Segurança em Comércio Eletrônico              #
#                                               #
# Instituição: Unisinos - Turma: 2021/02        #
#################################################

import argparse
from datetime import datetime
import os
from cryptography import x509
from cryptography.x509.base import Certificate
import requests

IS_SAFE=False

parser = argparse.ArgumentParser(description="cert-checker - Check if a certificate is trusted, based on a list of trusted root CA")
parser.add_argument('--certificate', action='store', type=str, required=True)
parser.add_argument('--trustedRootCert', action='store', type=str,required=True)
args=parser.parse_args()

certificateToCheckFileName=args.certificate
trustedRootFileName=args.trustedRootCert
    
subjectKeyIdentifier=x509.ObjectIdentifier("2.5.29.14")
CRLDistributionPoints=x509.ObjectIdentifier("2.5.29.31")
authorityKeyIdentifier=x509.ObjectIdentifier("2.5.29.35")
authorityInfoAccess=x509.ObjectIdentifier("1.3.6.1.5.5.7.1.1")
authorityInfoAccessCA_OSCP=x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1")
authorityInfoAccessCA_Issuer=x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2")

#### Variables necessarias do certificado a ser obtidas
certificateToCheckAuthorityKeyIdentifier=""
certificateToCheckAIA_CAIssuer=""
certificateToCheckAIA_OCSP=""
certificateToCheckCRL_List=[]

PARSED_CRLS=[]

TIMESTAMP_NOW=datetime.now().timestamp()

########### FUNCOES ###########

def parseCertificate(certificateData:bytes):
    parsedCertificate:Certificate
    try:
        certificateData.decode()
        # print("O formato do certificado parece ser PEM")
        fileFormat="PEM"
    except:
        # print("O formato do certificado parece ser DER")
        fileFormat="DER"
    
    if fileFormat=="PEM":
        try:
            parsedCertificate = x509.load_pem_x509_certificate(certificateData,backend=None)
        except Exception as e:
            print(e)
            print("Erro ao processar o certificado no formato PEM")
            
            try:
                parsedCertificate = x509.load_der_x509_certificate(certificateData,backend=None)
            except Exception as e:
                print(e)
                print("Erro ao processar o certificado no formato DER")
                exit(1)

    if fileFormat=="DER":
        try:
            parsedCertificate = x509.load_der_x509_certificate(certificateData,backend=None)
        except Exception as e:
            print(e)
            print("Erro ao processar o certificado no formato DER")

            try:
                parsedCertificate = x509.load_pem_x509_certificate(certificateData,backend=None)
            except Exception as e:
                print(e)
                print("Erro ao processar o certificado no formato PEM")
                exit(1)
    
    return parsedCertificate

def loadCertificateFile(certificateFileName:str):
    # Verify if file exist
    if not os.path.isfile(certificateFileName): 
        print("O certificado '"+certificateToCheckFileName+"' não foi encontrado.")
        exit(1)
    # Try to read file in binary mode
    try:
        certificateData = open(certificateFileName,mode='rb').read()
    except:
        print("Erro na leitura do certificado->"+certificateToCheckFileName)
        exit(1)
    return certificateData     

def requestRemoteFile(remoteFileURI:str):
    
    try:
        httpResponse = requests.get(remoteFileURI)
    except Exception as e:
        print("Erro ao obter o arquivo:",remoteFileURI)
        print(e)
        exit(1)
    
    if httpResponse.status_code != 200:
        print("Erro ao obter o arquivo, URI="+remoteFileURI+", status_code=%i",httpResponse.status_code)
        exit(1)

    remoteFile=httpResponse.content

    httpResponse.close()

    return remoteFile

############# PARSE REVOCATION LIST #################
def parseCertificateRevocationList(CRLData:bytes):
    parsedCertificateRevocationList:x509.CertificateRevocationList
    try:
        CRLData.decode()
        # print("O formato da CRL parece ser PEM")
        fileFormat="PEM"
    except:
        # print("O formato da CRL parece ser DER")
        fileFormat="DER"

    if fileFormat=="PEM":
        try:
            parsedCertificateRevocationList = x509.load_pem_x509_crl(CRLData,backend=None)
        except Exception as e:
            print(e)
            print("Erro ao processar a lista de certificados revogados no formato PEM")
            
            try:
                parsedCertificateRevocationList = x509.load_der_x509_crl(CRLData,backend=None)
            except Exception as e:
                print(e)
                print("Erro ao processar a lista de certificados revogados no formato DER")
                exit(1)

    if fileFormat=="DER":
        try:
            parsedCertificateRevocationList = x509.load_der_x509_crl(CRLData,backend=None)
        except Exception as e:
            print(e)
            print("Erro ao processar o certificado no formato DER")

            try:
                parsedCertificateRevocationList = x509.load_pem_x509_crl(CRLData,backend=None)
            except Exception as e:
                print(e)
                print("Erro ao processar o certificado no formato PEM")
                exit(1)
    
    return parsedCertificateRevocationList

############## Request CRL LIST ###################
def requestListOfCRL(listOfCRL:list):
    parsedCRLs=[]
    for url in listOfCRL:
        CRLData = requestRemoteFile(url)
        parsedCRLs.append(parseCertificateRevocationList(CRLData)) 
    return parsedCRLs
############## Validate Serial Number in CRL List ############
def validateSerialNumberInListOfCRL(certificateSerialNumber:x509.Certificate.serial_number,CRLList:list):
    # print(len(CRLList))
    print("Checking Revocation List: ",end=" ")
    for crl in CRLList:
        revokedCertificate = crl.get_revoked_certificate_by_serial_number(certificateSerialNumber) 
        if revokedCertificate is not None:
        #     print("\tO certificado nao esta na CRL, Certificado Valido")
        # else:
            print("\tCertificado Revogado!!!")
            print("\tSerial Number:", revokedCertificate.serial_number)
            print("\tData de revogacao:", revokedCertificate.revocation_date)
            print("Certificado Invalido!!!")
            exit(1)

    print("OK\n")

########### CHECK DATA OF CERTIFICATE ###########
def checkDataCertificate(certificateName:str,certificate:Certificate):
    if TIMESTAMP_NOW > certificate.not_valid_after.timestamp() or TIMESTAMP_NOW < certificate.not_valid_before.timestamp():
        print("***A validade do certificado \""+certificateName+"\" é invalida!***")
        exit(1)
    # else:
    #     print("Validade do certificado OK")
        

################# PARSE ROOT #################
trustedRootData=loadCertificateFile(trustedRootFileName)
trustedRoot=parseCertificate(trustedRootData)
trustedRootSubjectKeyIdentifier=trustedRoot.extensions.get_extension_for_oid(subjectKeyIdentifier).value.digest.hex()
checkDataCertificate(trustedRootFileName,trustedRoot)

# print("Trusted Root:",trustedRootFileName)
# print("\tSubject Key Identifier [",subjectKeyIdentifier.dotted_string,"], Hex Value:",trustedRootSubjectKeyIdentifier)
# print("\tNot valid Before: ",trustedRoot.not_valid_before)
# print("\tNot valid After: ",trustedRoot.not_valid_after)
# print("\tSerial Number: ",trustedRoot.serial_number)

######### PARSE CERTIFICATE TO CHECK #########
certificateToCheckData=loadCertificateFile(certificateToCheckFileName)
certificateToCheck=parseCertificate(certificateToCheckData)

certificateToCheckAuthorityKeyIdentifier=certificateToCheck.extensions.get_extension_for_oid(authorityKeyIdentifier).value.key_identifier.hex()
checkDataCertificate(certificateToCheckFileName,certificateToCheck)

certificateToCheckAIA=certificateToCheck.extensions.get_extension_for_oid(authorityInfoAccess).value
for oid in certificateToCheckAIA:

    if oid.access_method == authorityInfoAccessCA_Issuer:
        certificateToCheckAIA_CAIssuer = str(oid.access_location.value)
        continue
    
    if oid.access_method == authorityInfoAccessCA_OSCP:
        certificateToCheckAIA_OCSP = str(oid.access_location.value)
        continue

for CRLDistributionPoint in certificateToCheck.extensions.get_extension_for_oid(CRLDistributionPoints).value:
    for resource in CRLDistributionPoint.full_name:
        certificateToCheckCRL_List.append(str(resource.value))

PARSED_CRLS=requestListOfCRL(certificateToCheckCRL_List)

print("Certificado to be checked:",certificateToCheckFileName)
validateSerialNumberInListOfCRL(certificateToCheck.serial_number,PARSED_CRLS)
print("\tAuthority Key Identifier [",authorityKeyIdentifier.dotted_string,"], Hex Value:",certificateToCheckAuthorityKeyIdentifier)
print("\tAIA - CAIssuer [",authorityInfoAccessCA_Issuer.dotted_string,"]:",certificateToCheckAIA_CAIssuer)
print("\tAIA - OCSP [",authorityInfoAccessCA_OSCP.dotted_string,"]:",certificateToCheckAIA_OCSP)
print("\tCRL List [",CRLDistributionPoints.dotted_string,"]:",certificateToCheckCRL_List)
print("\tNot valid Before: ",certificateToCheck.not_valid_before)
print("\tNot valid After: ",certificateToCheck.not_valid_after)
print("\tSerial Number: ",certificateToCheck.serial_number,"\n\n")

authorityKeyIdentifierToCheck=certificateToCheckAuthorityKeyIdentifier

if certificateToCheckAuthorityKeyIdentifier == trustedRootSubjectKeyIdentifier:
    print("Certificado assinado pelo root!")
    exit(0)

def checkCA(uri:str):
    # print(uri)
    certCACRLs_List=[]
    certCA_CAIssuer=""
    # certCA_OCSP=""
    certCAData=requestRemoteFile(uri)
    certCA=parseCertificate(certCAData)
   
    print("Intermediate CA:",uri)

    certCAAuthorityKeyIdentifier=certCA.extensions.get_extension_for_oid(authorityKeyIdentifier).value.key_identifier
    certCASubjectKeyIdentifier=certCA.extensions.get_extension_for_oid(subjectKeyIdentifier).value.digest
    checkDataCertificate(uri,certCA)
    global authorityKeyIdentifierToCheck
    if certCASubjectKeyIdentifier.hex() != authorityKeyIdentifierToCheck:
        print("Authority and Subject ID mismatch!",certCASubjectKeyIdentifier.hex(),authorityKeyIdentifierToCheck)
        exit(1)

    if certCAAuthorityKeyIdentifier==None:
        print("\tSubject Key Identifier [",subjectKeyIdentifier.dotted_string,"], Hex Value:",certCASubjectKeyIdentifier.hex())
        print("\tNot valid Before: ",certCA.not_valid_before)
        print("\tNot valid After: ",certCA.not_valid_after)
        print("\tSerial Number: ",certCA.serial_number,"\n\n")
        return ""
    else:

        authorityKeyIdentifierToCheck=certCAAuthorityKeyIdentifier.hex()
        for CRLDistributionPoint in certCA.extensions.get_extension_for_oid(CRLDistributionPoints).value:
            for resource in CRLDistributionPoint.full_name:
                certCACRLs_List.append(str(resource.value))

        parsedCertCACRLs_List=requestListOfCRL(certCACRLs_List)

        validateSerialNumberInListOfCRL(certCA.serial_number,parsedCertCACRLs_List)

        certCAAuthorityInformationAccess=certCA.extensions.get_extension_for_oid(authorityInfoAccess).value
        for oid in certCAAuthorityInformationAccess:
            if oid.access_method == authorityInfoAccessCA_Issuer:
                # //print(str(oid.access_location.value))
                certCA_CAIssuer = str(oid.access_location.value)
                break

        print("\tAuthority Key Identifier [",authorityKeyIdentifier.dotted_string,"], Hex Value:",certCAAuthorityKeyIdentifier.hex())
        print("\tSubject Key Identifier [",subjectKeyIdentifier.dotted_string,"], Hex Value:",certCASubjectKeyIdentifier.hex())
        print("\tAIA - CAIssuer [",authorityInfoAccessCA_Issuer.dotted_string,"]:",certCA_CAIssuer)
        # print("\tAIA - OCSP [",authorityInfoAccessCA_OSCP.dotted_string,"]:",certificateToCheckAIA_OCSP)
        print("\tCRL List [",CRLDistributionPoints.dotted_string,"]:",certCACRLs_List)
        print("\tNot valid Before: ",certCA.not_valid_before)
        print("\tNot valid After: ",certCA.not_valid_after)
        print("\tSerial Number: ",certCA.serial_number,"\n\n")

        if certCAAuthorityKeyIdentifier.hex() == trustedRootSubjectKeyIdentifier:
            global IS_SAFE
            IS_SAFE=True
            certCA_CAIssuer=""
            
        
        return certCA_CAIssuer
    
END=False
certCA_URI=certificateToCheckAIA_CAIssuer

while not END:
    certCA_URI=checkCA(certCA_URI)
    if certCA_URI == "":
        END=True

print("Trusted Root:",trustedRootFileName)
print("\tSubject Key Identifier [",subjectKeyIdentifier.dotted_string,"], Hex Value:",trustedRootSubjectKeyIdentifier)
print("\tNot valid Before: ",trustedRoot.not_valid_before)
print("\tNot valid After: ",trustedRoot.not_valid_after)
print("\tSerial Number: ",trustedRoot.serial_number)

if IS_SAFE:
    print("\n*** O certificado",certificateToCheckFileName,"é confiavel! ***")
else:
    print("\n*** O certificado",certificateToCheckFileName,"NÃO é confiavel! ***")