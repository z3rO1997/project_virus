import sys
import zlib
import hashlib
import os

# 주어진 파일을 암호화한다.
def main():
    if len(sys.argv) != 2:
        print('Usage : kmake.py[file]')
        return

    fname = sys.argv[1]
    tname = fname

    fp = open(fname, 'r')
    buf = fp.read()
    fp.close()

    buf2 = zlib.compress(buf)  # 대상 파일 내용을 압축한다

    buf3 = ''
    for c in buf2:  # 0xFF로 압축된 내용을 XOR한다.
        buf3 += chr(ord(c) ^ 0xFF)

    buf4 = 'KAVM' + buf3  # 헤더를 생성한다.

    f = buf4
    for i in range(3):  # 지금까지의 내용을 MD5로 구한다.
        md5 = hashlib.md5()
        md5.update(f)
        f = md5.hexdigest()

    buf4 += f  # MD5를 암호화된 내용 뒤에 추가한다.

    kmd_name = fname.split('.')[0] + '.kmd'
    fp = open(kmd_name, 'wb')  # kmd 확장자로 암호 파일을 생성한다.
    fp.write(buf4)
    fp.close()

    print('{0} -> {1}'.format(fname, kmd_name))

if __name__ == '__main__':
    main()
