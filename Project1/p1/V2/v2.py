import os
import hashlib

f = open('DummyTest', 'rb')
fbuf = f.read()
f.close()

m = hashlib.md5()
m.update(fbuf)
fmd5 = m.hexdigest()

if fmd5 == 'a4443c9beccae3e034da175b40077152':
    print('Dummy Test Virus')
elif fmd5 == '44d88612fea8a8f36de82e1278abb02f':
    print('EICAR Test Virus')
else:
    print('No Virus')
