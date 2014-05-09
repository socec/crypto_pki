# pk = private key
# puk = public key
# ca = certificate authority

import time
from M2Crypto import X509, EVP, RSA, ASN1

# low-level functions

def pki_ca_issuer():
	"""
	Our default CA issuer name.
	"""
	issuer = X509.X509_Name()
	issuer.C = "US"
	issuer.CN = "ca_server"
	return issuer

def pki_cert_valid(cert, days=365):
	"""
	Make a cert valid from now and til 'days' from now.
	Args:
	   cert -- cert to make valid
	   days -- number of days cert is valid for from now.
	"""
	t = long(time.time())
	now = ASN1.ASN1_UTCTIME()
	now.set_time(t)
	expire = ASN1.ASN1_UTCTIME()
	expire.set_time(t + days * 24 * 60 * 60)
	cert.set_not_before(now)
	cert.set_not_after(expire)

def pki_request(bits, cn='localhost'):
	"""
	Create a X509 request with the given number of bits in they key.
	Args:
	  bits -- number of RSA key bits
	  cn -- common name in the request
	Returns a X509 request and the private key (EVP)
	"""
	pk = EVP.PKey()
	x = X509.Request()
	rsa = RSA.gen_key(bits, 65537, lambda: None)
	pk.assign_rsa(rsa)
	x.set_pubkey(pk)
	name = x.get_subject()
	name.C = "US"
	name.CN = cn
	x.sign(pk,'sha256')
	return x, pk

def pki_cacert():
	"""
	Make a CA certificate.
	Returns the certificate, private key and public key.
	"""
	req, pk = pki_request(1024)
	pkey = req.get_pubkey()
	cert = X509.X509()
	cert.set_serial_number(1)
	cert.set_version(1)
	pki_cert_valid(cert)
	cert.set_issuer(pki_ca_issuer())
	cert.set_subject(cert.get_issuer())
	cert.set_pubkey(pkey)
	cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
	cert.sign(pk, 'sha256')
	return cert, pk, pkey

def pki_cert(serial_number):
	"""
	Make a certificate.
	Returns a new cert.
	"""
	cert = X509.X509()
	cert.set_serial_number(serial_number)
	cert.set_version(1)
	pki_cert_valid(cert)
	return cert

# high-level functions - these are used

def pki_ca_init(ca_cert_file, ca_pk_file, ca_puk_file):
	"""
	Create CA certificate, CA private key and CA public key.
	Save them as files.
	"""
	ca_cert, ca_pk, ca_puk = pki_cacert()
	ca_cert.save_pem(ca_cert_file)
	ca_pk.save_key(ca_pk_file, cipher = None, callback = lambda: None)
	ca_puk.get_rsa().save_pub_key(ca_puk_file)

def pki_request_certificate_from_ca(name, cert_req_file, pk_file):
	"""
	Call from a client. Name is an id string that will go into certificate.
	Create a certificate request for CA and a private key.
	Save them as files.
	"""
	cert_req, pk = pki_request(1024, cn = name)
	cert_req.save_pem(cert_req_file)
	pk.save_key(pk_file, cipher = None, callback = lambda: None)

def pki_ca_issue_certificate_on_request(cert_req_file, ca_pk_file, serial_number, cert_file):
	"""
	Call from CA.
	Issue certificate based on the request. Serial number must not repeat in issued certificates.
	Save it as a file.
	"""
	ca_pk = EVP.load_key(ca_pk_file)  # load EVP for signing certificates
	cert_req = X509.load_request(cert_req_file)
	cert = pki_cert(serial_number)
	cert.set_subject(cert_req.get_subject())
	cert.set_pubkey(cert_req.get_pubkey())
	cert.sign(ca_pk, 'sha256')
	cert.save_pem(cert_file)

def pki_verify_certificate(cert_file, ca_cert_file):
	"""
	Call from a client.
	Verifies a client certificate by using CA certificate.
	Returns 1 if client certificate is valid, 0 otherwise.
	"""
	cert = X509.load_cert(cert_file)
	ca_cert = X509.load_cert(ca_cert_file)
	return cert.verify(ca_cert.get_pubkey())

def pki_encrypt_with_private_key(message, pk_file):
	"""
	Call from a client.
	Encrypts a message using a private key, so it can be decrypted with a public key.
	Returns encrypted message or string starting with "ERROR" in case of error.
	"""
	pk = RSA.load_key(pk_file) # load RSA for encryption
	try:
		encrypted = pk.private_encrypt(message, RSA.pkcs1_padding)
	except RSA.RSAError as e:
		return "ERROR encrypting " + e.message
	return encrypted

def pki_decrypt_with_certificate(message, cert_file):
	"""
	Call from a client.
	Decrypts a message crypted with a private key by using a public key from a certificate.
	Returns decrypted message or string starting with "ERROR" in case of error.
	"""
	cert = X509.load_cert(cert_file)
	puk = cert.get_pubkey().get_rsa() # get RSA for decryption
	try:
		decrypted = puk.public_decrypt(message, RSA.pkcs1_padding)
	except RSA.RSAError as e:
		return "ERROR decrypting " + e.message
	return decrypted



# ==========
# EXAMPLE
# ==========

# declare file locations

ca_cert_file = "ca_cert.pem"
ca_pk_file = "ca_pk.pem"
ca_puk_file = "ca_puk.pem"

cert_req_file = "cert_req.pem"
pk_file = "pk.pem"
cert_file = "cert.pem"


# first initialize CA, creating CA certificate, CA public and CA private key
pki_ca_init(ca_cert_file, ca_pk_file, ca_puk_file)

# then a client can request a certificate from CA, creating certificate request and client private key
# client also receives CA certificate and stores it locally
pki_request_certificate_from_ca("client", cert_req_file, pk_file)

# then CA approves and issues the certificate for client and also stores this certificate locally
pki_ca_issue_certificate_on_request(cert_req_file, ca_pk_file, 2, cert_file)

# a client can verify another client's certificate by using CA certificate
print pki_verify_certificate(cert_file, ca_cert_file)


# testing encryption and decryption
message = "hello world"
print message

# a message can be encryted with client private key (error is reported in the response)
crypted = pki_encrypt_with_private_key(message, pk_file)
print crypted

# a message can be decrypted with client certificate, more precisely with client public key (error is reported in the response)
decrypted = pki_decrypt_with_certificate(crypted, cert_file)
print decrypted
