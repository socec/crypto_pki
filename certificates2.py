# http://pythonhosted.org//pyOpenSSL/api.html
# http://pki-tutorial.readthedocs.org/en/latest/
# https://pypi.python.org/pypi/M2Crypto
# http://blog.richardknop.com/2012/08/create-a-self-signed-x509-certificate-in-python/

from M2Crypto import RSA

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

def create_certificate(id_tag, public_key):
	return a


pub_key_path = "pub.key"
prv_key_path = "prv.key"

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

f = open(pub_key_path, 'r')
a = f.read()
print a
f.close