import os
import hashlib

# 1단계 단순한 바이러스 탐색
# fp = open('eicar.txt', 'r') #의심되는 파일을 찾아서 읽어들인다
# fbuf = fp.read()
# fp.close()
#
# if fbuf[0:3] == 'X5O': #의심되는 파일의 첫번째 3byte를 읽어들여 검사
#     print('Virus')
#     os.remove('eicar.txt')
# else:
#     print('No Virus')

#2단계 바이러스 탐색을 해쉬를 사용하여 정확하게 한다
fp = open('eicar.txt', 'rb') #의심되는 파일을 찾아서 읽어들인다
fbuf = fp.read()
fp.close()

m = hashlib.md5()
m.update(fbuf)
fmd5 = m.hexdigest()

if fmd5 == '44d88612fea8a8f36de82e1278abb02f': #의심되는 파일의 첫번째 3byte를 읽어들여 검사
    print('Virus')
    os.remove('eicar.txt')
else:
    print('No Virus')

# 감상평
# 1.바이러스 진단은 바이너리 읽기모드 사용해야한다.
# 2.진단 문자열은 최소 10Byte 이상을 사용하는게 좋다.
# 3.MD5 해시를 이용하여 진단할 수 있는 악성코드는 바이러스 유형을 제외한 파일 자체가 악성코드인 트로이목마 웜 백도어 등이다.