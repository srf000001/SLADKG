from gmssl import *
sm2 = Sm2Key()
sm2.generate_key()

sm2.export_encrypted_private_key_info_pem('sm2.pem', 'password')
private_key = Sm2Key()
private_key.import_encrypted_private_key_info_pem('sm2.pem', 'password')