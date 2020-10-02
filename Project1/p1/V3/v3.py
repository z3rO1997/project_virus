import os
import hashlib
import sys

VirusDB = [] # 악성코드 패턴은 모두 virus.db에 존재한다
vdb = [] # 가공된 악성코드 DB가 저장된다.
vsize = [] # 악성코드의 파일 크기만 저장한다.

# virus.db 파일에서 악성코드 패턴을 읽는다.
def LoadVirusDB():
    fp = open('Virus.db', 'rb') # 악성코드 패턴을 연다

    while True:
        line = fp.readline() # 악성코드 패턴을 한 줄 읽는다
        if not line: break

        line = line.strip()
        VirusDB.append(line) # 악성코드 패턴을 VirusDB에 추가

    fp.close()

# VirusDB를 가공하여 vdb에 저장한다.
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':') # 세미콜론을 기준으로 분해
        t.append(v[1]) # MD5 해시를 저장한다
        t.append(v[2]) # 악성코드 이름을 저장
        vdb.append(t) # 최종은 vdb에 저장한다

        size = int(v[0]) # 악성코드 파일 크기

        if vsize.count(size) == 0: # 이미 해당 크기가 등록되었나?
            vsize.append(size)

# 악성코드를 검사한다
def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5: # MD5 해시가 같은지 비교
            return True, t[1] # 악성코드의 이름과 함께 리턴

    return False, '' # 악성코드가 발견되지 않음

if __name__ == '__main__':
    LoadVirusDB() #악성코드 패턴을 파일에서 읽는다.
    MakeVirusDB() #악성코드 DB가공

    # 커맨드라인으로 악성코드를 검사할 수 있음
    # 커맨드라인의 입력 방식을 체크한다
    if len(sys.argv) != 2:
        print('Usage : antivirus.py[file]')
        exit(0)
    fname = sys.argv[1] # 악성코드 검사 대상 파일

    size = os.path.getsize(fname) # 검사 대상 파일 크기를 구한다.

    if vsize.count(size):
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5) # 악성코드 검사
        if ret == True:
            print('{0} : {1}'.format(fname, vname))
            os.remove(fname)
        else:
            print(ret, vname)
            print('{0} : OK'.format(fname))
    else:
        print('{0} : OK'.format(fname))

# virus.db를 누군가 변조할 가능성이 존재하니 암호화와 복호화 코드를 추가해야함
