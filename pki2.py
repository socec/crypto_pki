from M2Crypto import RSA, EVP, X509, ASN1
import time

def rsa_key_pair_generate():
	# 1024 is the size of the key
	# 65537 encryption standard used as a default
	# lambda used to avoid graphical feedback when generating key
	rsa_key= RSA.gen_key(1024, 65537, callback = lambda x, y, z:None)
	return rsa_key

def rsa_key_pair_save(rsa_key, private_key_file, public_key_file):
	rsa_key.save_key (private_key_file, cipher = None) # if using cipher we would have to use a passphrase
	rsa_key.save_pub_key (public_key_file)

def cert_issuer():
	issuer = X509.X509_Name()
	issuer.C = "US"
	issuer.CN = "ca_testing_server"
	issuer.ST = 'CA'
	issuer.L = 'San Francisco'
	issuer.O = 'ca_yelp'
	issuer.OU = 'ca_testing'
	return issuer

def cert_valid(cert, days=365):
	t = long(time.time())
	now = ASN1.ASN1_UTCTIME()
	now.set_time(t)
	expire = ASN1.ASN1_UTCTIME()
	expire.set_time(t + days * 24 * 60 * 60)
	cert.set_not_before(now)
	cert.set_not_after(expire)





def create_certificate_request(subject_rsa_key):
	# converting RSA key into a PKey(), a public key which is stored in the certificate
	pkey = EVP.PKey()
	pkey.assign_rsa(subject_rsa_key)
	# create certificate
	cert = X509.X509()
	cert.set_pubkey(pkey)
	subject_id = X509.X509_Name()
	subject_id.Email = "one@foo.com"
	cert.set_subject(subject_id)
	# e
	# time for certificate to stay valid
	current_time = ASN1.ASN1_UTCTIME()
	current_time.set_time( int(time.time()) - 60*60*24) # 1 day before now
	expire_time = ASN1.ASN1_UTCTIME()
	expire_time.set_time( int(time.time()) + 60*60*24) # 1 day after now
	cert.set_not_before(current_time)
	cert.set_not_after(expire_time)
	return cert

def create_certificate_issuer_part(issuer_rsa_key):
	# converting RSA key into a PKey(), a public key which is stored in the certificate
	pkey = EVP.PKey()
	pkey.assign_rsa(issuer_rsa_key)
	# time for certificate to stay valid
	current_time = ASN1.ASN1_UTCTIME()
	current_time.set_time( int(time.time()) - 60*60*24) # 1 day before now
	expire_time = ASN1.ASN1_UTCTIME()
	expire_time.set_time( int(time.time()) + 60*60*24) # 1 day after now
	# create certificate
	cert = X509.X509()
	issuer_id = X509.X509_Name()
	issuer_id.Email = "two@foo.com"
	cert.set_issuer_name(issuer_id)
	cert.set_not_before(current_time)
	cert.set_not_after(expire_time)
	return cert

def save_certificate(cert, cert_file):
	cert.save_pem(cert_file)

# =================

key = rsa_key_pair_generate()
rsa_key_pair_save(key, "Alice-private", "Alice-public")

#cert_sub = create_certificate_subject_part(key)
#cert_iss = create_certificate_issuer_part(key)

cert1 = X509.X509()
cert1 = create_certificate_subject_part(key)
save_certificate(cert1, "Alice-cert-req")
print "BEFORE SAVING"
print cert1.as_text()

cert = X509.load_cert("Alice-cert-req", format = X509.FORMAT_PEM)
print "AFTER LOADING"
print cert.as_text()

# create certificate
issuer_id = X509.X509_Name()
issuer_id.Email = "two@foo.com"
cert.set_issuer_name(issuer_id)
current_time = ASN1.ASN1_UTCTIME()
current_time.set_time( int(time.time()) - 60*60*24) # 1 day before now
expire_time = ASN1.ASN1_UTCTIME()
expire_time.set_time( int(time.time()) + 60*60*24) # 1 day after now
cert.set_not_before(current_time)
cert.set_not_after(expire_time)
print "AFTER PLAYING"
print cert.as_text()

key2 = generate_RSA_key_pair()
pkey = EVP.PKey()
pkey = pkey.assign_rsa(key2)
print "top"
cert.sign(key2, md="sha256")
print "top"

save_certificate(cert, "Alice-cert")

print "as pem"
print cert.as_pem()

print "as text"
print cert.as_text()