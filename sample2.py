from M2Crypto import RSA, EVP, X509, ASN1
import time

# Generating a Random RSA key pair (public and private):
key= RSA.gen_key(512, 65537, callback = lambda x, y, z:None)
#512 is the size of the key
#65537 encryption standard use it as a default

# Saving the generated public and private key:
key.save_key ('Alice-private.pem', None)
key.save_pub_key ('Alice-public.pem')
# None is a specified password for testing purposes there is none
# The file can be created in a specific directory /local/temp/Alice-private.pem

# Converting the RSA key into a PKey() which is stored in a certificate:
pkey = EVP.PKey()
pkey.assign_rsa(key)

# To create a X509 certificate using M2Crypto:

# time for certificate to stay valid
cur_time = ASN1.ASN1_UTCTIME()
cur_time.set_time(int(time.time()) - 60*60*24)
expire_time = ASN1.ASN1_UTCTIME()
# Expire certs in 1 day.
expire_time.set_time(int(time.time()) + 60 * 60 * 24)
# creating a certificate
cert = X509.X509()
cert.set_pubkey(pkey)
cs_name = X509.X509_Name()
cs_name.C = "US"
cs_name.CN = "8080"
cs_name.Email = "fake@foo.com"
cert.set_subject(cs_name)
cert.set_issuer_name(cs_name)
cert.set_not_before(cur_time)
cert.set_not_after(expire_time)
# self signing a certificate
cert.sign(pkey, md="sha256")
cert.save_pem("cert")

#This will create a "cert" file in your directory which can be loaded later on. Or you can use the cert object to convert into a string to send it through a socket EG:
message = cert.as_pem()
print message

# Once you receive the certificate as a string the way to convert it to a certificate object is:
m2cert = X509.load_cert_string(message, format = X509.FORMAT_PEM)

# you can print the certificate object as a more readable string with this line:
print m2cert.as_text()

# To extract an RSA key which can be used for encoding you use this:
pkey= m2cert.get_pubkey()
rsa_key_pub = pkey.get_rsa()

#===
message = "trololo"
#===

# to encrypt a message using the public key above:
crypto = rsa_key_pub.public_encrypt(message, RSA.pkcs1_oaep_padding)

# to decrypt a message using the private key, which you saved earlier, you need to load it first:
rsa_key_pri= RSA.load_key('Alice-private.pem')

# once loaded use the command to decrypt:
decyphered = rsa_key_pri.private_decrypt(crypto, RSA.pkcs1_oaep_padding)
print decyphered
