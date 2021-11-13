import argparse
import os
import mimetypes
from typing import NewType
from cryptography import x509
# from cryptography.hazmat.backends import default_backend
# import cryptography

parser = argparse.ArgumentParser(description="cert-checker - Check if a certificate is trusted, based on a list of trusted root CA")
parser.add_argument('--certificate', action='store', type=str, required=True)
parser.add_argument('--trustedRootCert', action='store', type=str,required=True)
args=parser.parse_args()

certificateToCheckFileName=args.certificate
trustedRootFileName=args.trustedRootCert

########### READ CERTIFICATE ###########

# Verify if file exist
if os.path.isfile(certificateToCheckFileName): 
    print("O certificado a ser verificado '"+certificateToCheckFileName+"' foi encontrado.")
else:
    print("O certificado a ser verificado '"+certificateToCheckFileName+"' não foi encontrado.")
    exit(1)

# Try to read file in binary mode
try:
    certificateToCheckData = open(certificateToCheckFileName,mode='rb').read()
except:
    print("Erro na leitura do certificado a ser validado.")
    exit(1)

# Try to parse certificate file
try:
    certificateToCheck = x509.load_pem_x509_certificate(certificateToCheckData,backend=None)
    
except Exception as e:
    print(e)
    print("Erro ao processar o certificado a ser validado")
    exit(1)

########### READ ROOT CERTIFICATE ###########

# Verify if file exist
if os.path.isfile(trustedRootFileName): 
    print("O certificado a ser verificado '"+trustedRootFileName+"' foi encontrado.")
else:
    print("O certificado a ser verificado '"+trustedRootFileName+"' não foi encontrado.")
    exit(1)

# Try to read file in binary mode
try:
    trustedRootCertData = open(trustedRootFileName,mode='rb').read()
except:
    print("Erro na leitura do certificado a ser validado.")
    exit(1)

# Try to parse certificate file
# try:
trustedRoot = x509.load_der_x509_certificate(trustedRootCertData,backend=None)
# except Exception as e:
#     print(e)
#     print("Erro ao processar o certificado root")
#     exit(1)

#### Ler data de validade dos certificados ####






#### Obter Subject Key do Root

