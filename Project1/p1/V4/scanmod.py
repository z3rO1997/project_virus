import os
import hashlib


# 악성코드 검사한다.
def SearchVDB(vdb, fmd5):
    for t in vdb:
        if t[0] == fmd5:  # MD5 해시가 같은지 비교
            return True, t[1]

    return False, ''

# MD5를 이용해서 악성코드를 검사한다.
def ScanMD5(vdb, vsize, fname):
    ret = False  # 바이러스 발견유무
    vname = ''  # 바이러스 이름

    size = os.path.getsize(fname)  # 검사 대상 파일크기를 구한다.
    if vsize.count(size):
        fp = open(fname, 'r')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vanme = SearchVDB(vdb, fmd5)

    return ret, vname
