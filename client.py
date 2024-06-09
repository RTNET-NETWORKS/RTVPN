#!/usr/bin/python3

# This script initiates a connection with a RTVPN server.

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import sys
import socket

def generate_rsa_key_pair():
	# Générer une paire de clés RSA
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	public_key = private_key.public_key()

	# Sérialiser la clé privée au format PEM et l'enregistrer dans un fichier
	with open("private_key.pem", "wb") as f:
		private_key_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)
		f.write(private_key_pem)

	# Sérialiser la clé publique au format PEM
	public_key_pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

    # Encoder la clé publique en base64 avant de l'enregistrer dans la base de données
	encoded_public_key = base64.b64encode(public_key_pem).decode()

	# Enregistrer la clé publique dans la base de données (remplacez "user1" par le nom d'utilisateur approprié)
	print("Clef privée :")
	print(private_key_pem.decode())
	print("")
	print("Clef publique :")
	print(public_key_pem.decode())
	with open("public_key.pem", "wb") as f:
		f.write(public_key_pem)

	return private_key_pem, public_key_pem

if not os.path.exists('private_key.pem'):
	private_key, public_key = generate_rsa_key_pair()
	print("Paire de clefs crées !")
else:
	with open('private_key.pem', 'rb') as f:
		private_key = f.read()
	with open('public_key.pem', 'rb') as f:
		public_key = f.read()
	
if not sys.argv:
	print("An IP address must be given !")
	exit(1)
	
ip = sys.argv[1]
if sys.argv[2]:
	port = sys.argv[2]
else:
	port = 5010

def authentication(ip,port,private_key,public_key):
	print("test")