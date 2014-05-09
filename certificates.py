# tutorial about PKI
# http://pki-tutorial.readthedocs.org/en/latest/

# get "M2Crypto" from: https://pypi.python.org/pypi/M2Crypto
# also need "setuptools" from : https://pypi.python.org/pypi/setuptools/3.6
# also need "swig" on Linux... not sure on Windows

# useful reading
# http://blog.richardknop.com/2012/08/create-a-self-signed-x509-certificate-in-python/
# http://sheogora.blogspot.com/2012/03/m2crypto-for-python-x509-certificates.html

from M2Crypto import RSA, X509

def generate_RSA_keypair():
	key = RSA.gen_key(1024, 65537, callback = lambda x, y, z:None)
	return key

def save_public_key(key, public_key_file):
	key.save_pub_key(public_key_file)

def save_private_key(key, private_key_file):
	key.save_key(private_key_file, cipher = None)

def load_public_key(public_key_file):
	key = RSA.load_pub_key(public_key_file)
	return key

def load_private_key(private_key_file):
	key = RSA.load_key(private_key_file, callback = lambda x, y, z:None)
	return key

def create_certificate_request(id_tag, key):
	a = 1
	return a


pub_key_path = "pub.key"
prv_key_path = "prv.key"
cert_req_path = "cert.req"

key = generate_RSA_keypair()
save_public_key(key, pub_key_path)
save_private_key(key, prv_key_path)

data = "abcdefgh"
print data

pubkey = load_public_key(pub_key_path)
edata = pubkey.public_encrypt(data, RSA.pkcs1_oaep_padding)
print edata

prvkey = load_private_key(prv_key_path)
ddata = prvkey.private_decrypt(edata, RSA.pkcs1_oaep_padding)
print ddata

req = X509.Request()
req.set_pubkey(pubkey)
req.set_subject("miki")
req.save(cert_req_path, format = FORMAT_PEM)

