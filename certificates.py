from Crypto.PublicKey import RSA

def generate_RSA_keypair():
	from Crypto import Random 
	key = RSA.generate(1024, Random.new().read) 
	return key

def save_public_key(public_key_file, key):
	f = open(public_key_file, 'wb')
	f.write(key.publickey().exportKey())
	f.close

def save_private_key(private_key_file, key):
	f = open(private_key_file, 'wb')
	f.write(key.exportKey())
	f.close

def load_public_key(public_key_file):
	f = open(public_key_file, 'r')
	key = f.read()
	f.close
	return RSA.importKey(key)

def load_private_key(private_key_file):
	f = open(private_key_file, 'r')
	key = f.read()
	f.close
	return RSA.importKey(key)

def create_certificate(id_tag, public_key):
	return a


pub_loc = "pub.key"
prv_loc = "prv.key"

key = generate_RSA_keypair()
save_public_key(pub_loc, key)
save_private_key(prv_loc, key)

data = "abcdefgh"
print data

pubkey = load_public_key(pub_loc)
edata = pubkey.encrypt(data, 32)
print edata[0]

prvkey = load_private_key(prv_loc)
ddata = prvkey.decrypt(edata)
print ddata