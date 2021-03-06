import sys
import os
import hashlib

VirusDB = [
    '68:44d88612fea8a8f36de82e1278abb02f:EICAR Test',
    '65:a4443c9beccae3e034da175b40077152:Dummy Test'
] # 악성코드의 크기가 추가된 DB

vdb = [] # 가공된 악성코드 DB
vsize = [] # 악성코드의 파일 크기만 저장한다.

# VirusDB를 가공하여 vdb에 저장한다.
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':') # 세미콜론을 기준으로 분해
        t.append(v[1]) # MD5 해시를 저장한다
        t.append(v[2]) # 악성코드 이름을 저장
        vdb.append(t) # 최종은 vdb에 저장한다

        size = int(v[0]) #악성코드 파일 크기
        if vsize.count(size) == 0: #이미 해당 크기가 등록되었나?
            vsize.append(size)

def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5: # MD5 해시가 같은지 비교
            return True, t[1] # 악성코드의 이름과 함께 리턴
    return False, ''

if __name__ == '__main__':
    MakeVirusDB() #악성코드 DB가공

    # 커맨드라인으로 악성코드를 검사할 수 있음
    # 커맨드라인의 입력 방식을 체크한다
    if len(sys.argv) != 2:
        print('Usage : antivirus.py[file]')
        exit(0)
    fname = sys.argv[1] # 악성코드 검사 대상 파일

    size = os.path.getsize(fname)# 검사 대상 파일 크기를 구한다.
    if vsize.count(size):
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
    else:
        print('{0} : OK'.format(fname))
        
# open과 read의 사용횟수를 줄여서 성능을 증가시켰다