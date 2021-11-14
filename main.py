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


def requestCA(CAIssuerURI:str):
    
    try:
        httpResponse = requests.get(CAIssuerURI)
    except Exception as e:
        print("Erro ao acessar o certificado",CAIssuerURI)
        print(e)
        exit(1)
    
    if httpResponse.status_code is not 200:
        print("Erro ao obter certificado, CA="+CAIssuerURI+", status_code=%i",httpResponse.status_code)
        exit(1)

    certCA=httpResponse.content

    httpResponse.close()

    return certCA


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
if datetime.now().timestamp() > trustedRoot.not_valid_after.timestamp() or datetime.now().timestamp() < trustedRoot.not_valid_before.timestamp():
    print("***A validade do certificado \""+trustedRootFileName+"\" é invalida!***")
    exit(1)
else:
    print("\tValidade do certificado OK")

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
if datetime.now().timestamp() > certificateToCheck.not_valid_after.timestamp() or datetime.now().timestamp() < certificateToCheck.not_valid_before.timestamp():
    print("***A validade do certificado \""+certificateToCheckFileName+"\" é invalida!***")
    exit(1)
else:
    print("\tValidade do certificado OK")
##############################################

certCAData=requestCA(certificateToCheckAIA_CAIssuer)

certCA=parseCertificate(certCAData)

certCAAuthorityKeyIdentifier=certCA.extensions.get_extension_for_oid(authorityKeyIdentifier).value.key_identifier.hex()
print("\n\ncertificate To Check -> Authority Key Identifier:\n\tOID: [",authorityKeyIdentifier.dotted_string,"], Hex Value:",certificateToCheckAuthorityKeyIdentifier)

if certCAAuthorityKeyIdentifier==trustedRootSubjectKeyIdentifier:
    print("Certificado OK")