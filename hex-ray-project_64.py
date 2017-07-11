#-*- coding: utf-8 -*-
#build: python 2.7

from idaapi import *
from idautils import *

cursor = ""
fname = ""
se = None

def main()  :
    global cursor # 전역변수 cursor
    # 커서 위치 에러 탐색
    try :
        cursor = ScreenEA()
        go(Chunks(cursor).next())
    except :
        print "Error!! Please Place To Right Space\n"*10
    out()

def go(se)    :

    # 함수 이름 설정
    global fname
    fname = GetFunctionName(cursor)

    #
    for mem in range(se[0], se[1]) :
        try :
            disas_list = {
                'instruction' : GetMnem(mem),
                'op_first' : GetOpnd(mem, 0), # string
                'op_first_value' : self.unsigned2signed(GetOperandValue(mem, 0)), # int
                'op_second' : GetOpnd(mem, 1), # string
                'op_second_value' : self.unsigned2signed(GetOperandValue(mem, 1)) # int
            }

            print disas_list
        except :
            print "LOL"


def out()   :
    filename = fname + "_func.c"

    func = "" + \
    "int " + fname + "(){" + "\n"\
        + "\n"\
        + "\n"\
        + "\n"\
    "}"

    print "SUHOSIN Writing at " + filename
    f = open(filename, "w")
    f.write(func)
    f.close()

if __name__ == '__main__':
    main()
