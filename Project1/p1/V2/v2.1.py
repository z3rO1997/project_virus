import sys
import os
import hashlib

VirusDB = [
    '44d88612fea8a8f36de82e1278abb02f:EICAR Test',
    'a4443c9beccae3e034da175b40077152:Dummy Test'
] # 악성코드 DB

vdb = [] # 가공된 악성코드 DB

def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':') # 세미콜론을 기준으로 분해
        t.append(v[0]) # MD5 해시를 저장한다
        t.append(v[1]) # 악성코드 이름을 저장
        vdb.append(t) # 최종은 vdb에 저장한다

def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5: # MD5 해시가 같은지 비교
            return True, t[1]
    return False, ''

if __name__ == '__main__':
    MakeVirusDB() #악성코드 DB가공

    # 커맨드라인으로 악성코드를 검사할 수 있음
    # 커맨드라인의 입력 방식을 체크한다
    if len(sys.argv) != 2:
        print('Usage : antivirus.py[file]')
        exit(0)
    fname = sys.argv[1] # 악성코드 검사 대상 파일

    fp = open(fname, 'rb')
    buf = fp.read()
    fp.close()

    m = hashlib.md5()
    m.update(buf)
    fmd5 = m.hexdigest()

    ret, vname = SearchVDB(fmd5)# 악성코드 검사
    if ret == True:
        print('{0} : {1}'.format(fname, vname))
        os.remove(fname)
    else:
        print('{0} : OK'.format(fname))

#속도가 느려질 가능성 존재
