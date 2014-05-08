# http://pythonhosted.org//pyOpenSSL/api.html
# http://pki-tutorial.readthedocs.org/en/latest/
# https://pypi.python.org/pypi/M2Crypto
# http://blog.richardknop.com/2012/08/create-a-self-signed-x509-certificate-in-python/

from M2Crypto import RSA

key = RSA.gen_key(1024, 65537, callback = lambda x, y, z:None)
key.save_key("mypriv", cipher = None)
key.save_pub_key("mypub")
key.save_pem("mypem", cipher = None)
