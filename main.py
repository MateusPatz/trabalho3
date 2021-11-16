import argparse
from datetime import datetime
import os
from cryptography import x509
from cryptography.x509.base import Certificate
import requests
from requests.models import Response

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
        print("O formato do certificado parece ser PEM")
        fileFormat="PEM"
    except:
        print("O formato do certificado parece ser DER")
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
    
    if httpResponse.status_code is not 200:
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
        print("O formato da CRL parece ser PEM")
        fileFormat="PEM"
    except:
        print("O formato da CRL parece ser DER")
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
    for url in listOfCRL:
        CRLData = requestRemoteFile(url)
        PARSED_CRLS.append(parseCertificateRevocationList(CRLData)) 

############## Validate Serial Number in CRL List ############
def validateSerialNumberInListOfCRL(certificateSerialNumber:x509.Certificate.serial_number,CRLList:list):
    print(len(CRLList))
    print("\nChecking Revocation List: ")
    for crl in CRLList:
        revokedCertificate = crl.get_revoked_certificate_by_serial_number(certificateSerialNumber) 
        if revokedCertificate is None:
            print("\tO certificado nao esta na CRL, Certificado Valido")
        else:
            print("\tCertificado Revogado!!!")
            print("\tSerial Number:", revokedCertificate.serial_number)
            print("\tData de revogacao:", revokedCertificate.revocation_date)
            print("Certificado Invalido!!!")
            return False
    
    return True

########### CHECK DATA OF CERTIFICATE ###########
def checkDataCertificate(certificateName:str,certificate:Certificate):
    if TIMESTAMP_NOW > certificate.not_valid_after.timestamp() or TIMESTAMP_NOW < certificate.not_valid_before.timestamp():
        print("***A validade do certificado \""+certificateName+"\" é invalida!***")
        return False
    else:
        print("\tValidade do certificado OK")
        return True

########### READ CERTIFICATE ###########

certificateToCheckData=loadCertificateFile(certificateToCheckFileName)
certificateToCheck=parseCertificate(certificateToCheckData)

trustedRootData=loadCertificateFile(trustedRootFileName)
trustedRoot=parseCertificate(trustedRootData)

################# PARSE ROOT #################
trustedRootSubjectKeyIdentifier=trustedRoot.extensions.get_extension_for_oid(subjectKeyIdentifier).value.digest.hex()
print("trusted Root Subject Key Identifier:\n\tOID: [",subjectKeyIdentifier.dotted_string,"], Hex Value:",trustedRootSubjectKeyIdentifier)
print("\tNot valid Before: ",trustedRoot.not_valid_before)
print("\tNot valid After: ",trustedRoot.not_valid_after)
print("\tSerial Number: ",trustedRoot.serial_number)

##### Check data valid:
checkDataCertificate(trustedRootFileName,trustedRoot)

##############################################

######### PARSE CERTIFICATE TO CHECK #########
#### Get AuthorityKeyIdentifier from certificateToCheck
certificateToCheckAuthorityKeyIdentifier=certificateToCheck.extensions.get_extension_for_oid(authorityKeyIdentifier).value.key_identifier.hex()
print("\n\ncertificate To Check -> Authority Key Identifier:\n\tOID: [",authorityKeyIdentifier.dotted_string,"], Hex Value:",certificateToCheckAuthorityKeyIdentifier)

##### Get AuthorityInformationAccess from certificateToCheck
certificateToCheckAIA=certificateToCheck.extensions.get_extension_for_oid(authorityInfoAccess).value

for oid in certificateToCheckAIA:

    if oid.access_method == authorityInfoAccessCA_Issuer:
        certificateToCheckAIA_CAIssuer = str(oid.access_location.value)
        continue
    
    if oid.access_method == authorityInfoAccessCA_OSCP:
        certificateToCheckAIA_OCSP = str(oid.access_location.value)
        continue

print("\tAIA - CAIssuer:",certificateToCheckAIA_CAIssuer)
print("\tAIA - OCSP:",certificateToCheckAIA_OCSP)

##### Get CRLDistributionPoints from certificateToCheck
for CRLDistributionPoint in certificateToCheck.extensions.get_extension_for_oid(CRLDistributionPoints).value:
    for resource in CRLDistributionPoint.full_name:
        certificateToCheckCRL_List.append(str(resource.value))

print("\tCRL List:",certificateToCheckCRL_List)
print("\tNot valid Before: ",certificateToCheck.not_valid_before)
print("\tNot valid After: ",certificateToCheck.not_valid_after)
print("\tSerial Number: ",certificateToCheck.serial_number)

##### Check data valid:
checkDataCertificate(certificateToCheckFileName,certificateToCheck)
##############################################

certCAData=requestRemoteFile(certificateToCheckAIA_CAIssuer)

certCA=parseCertificate(certCAData)

certCAAuthorityKeyIdentifier=certCA.extensions.get_extension_for_oid(authorityKeyIdentifier).value.key_identifier.hex()
print("\n\ncertificate To Check -> Authority Key Identifier:\n\tOID: [",authorityKeyIdentifier.dotted_string,"], Hex Value:",certificateToCheckAuthorityKeyIdentifier)

if certCAAuthorityKeyIdentifier==trustedRootSubjectKeyIdentifier:
    print("Emissor Root Confiavel, Certificado OK")
else:
    print("O emissor root desse certificado nao esta na lista de roots confiaveis")
    exit(1)

############ Validacao CRL #######################

requestListOfCRL(certificateToCheckCRL_List)

validateSerialNumberInListOfCRL(certificateToCheck.serial_number,PARSED_CRLS)