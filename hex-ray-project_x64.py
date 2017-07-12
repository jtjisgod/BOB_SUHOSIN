#-*- coding: utf-8 -*-
#build: python 2.7

from idaapi import *
from idautils import *
import re


# 버퍼를 파일로 출력
def createFile(fileName, source_code):
    f = open(fileName, "w")
    f.write(source_code)
    f.close()
    return

class Hexray():
    movCount = 0
    source_code = ""
    disas_list = {}
    var_size = 0
    var_list = []
    registers = {
        'eax' : 0,
        'ebx' : 0,
        'ecx' : 0,
        'edx' : 0,
        'edi' : 0,
        'esi' : 0,
        'ebp' : 0,
        'esp' : 0
    }

    removed_canary = False # 더미 제거상태
    init_vars = False # 지역변수 선언상태
    func_is_main = False # 일반 함수와 main함수의 구조가 약간 다르니까 이 플래그로 나중에 더미제거할 때 예외처리
    indent = 0 # 주석
    funcName = ""

    # 주소를 넘겨주면 해당 커서 영역을 Hex-ray하기위한 초기화를 진행
    def __init__(self, currentAddress):
        segStart = SegStart(currentAddress)
        segEnd = SegEnd(currentAddress)

        funcStart = 0
        for func in Functions(segStart, segEnd):
            if funcStart == 0:
                funcStart = func
                continue

            funcEnd = func

            if funcStart <= currentAddress and currentAddress < funcEnd:
                self.hexrayStartAddrss = funcStart
                self.hexrayEndAddrss = funcEnd

            funcStart = func
        return


    # 문자열을 파싱하여 주어진 두 문자열 사이에 있는 문자열을 반환
    def parseString(f, l, data):
        key = re.search(re.escape(f) + '(.*?)' + re.escape(l), data)
        if key == None:
            return None
        return key.group(1)


    # 함수 영역의 시작과 끝을 출력 (디버깅용)
    def printRange(self):
        print "Start: %x" % self.hexrayStartAddrss
        print "End: %x" % self.hexrayEndAddrss
        return


    # int32로 변환 (야매인데 잘됨)
    def unsigned2signed(self, t):
        if t > 2147483647:
            t -= 4294967296
        return t


    # 인던트 추가해서 반환
    def add_sourcecode(self, buf):
        chunk = ""
        for x in range(0, self.indent):
            chunk += "    "
        chunk += buf
        chunk += "\n"
        return chunk

    # 함수 처리
    def handler_function(self, start, end, parameter_count):
        chunk = ""

        address = start
        while address < end:
            print "FUNC:: " + self.disas_list[address]['disas']
            address = NextHead(address)

        return chunk


    # 소스코드 생성하는 부분 (재귀함수)
    def hexray_opcodes(self, start, end):
        chunk = ""
        if start == end:
            try :
                chunk += "return " + self.registers['eax'].split("+")[1].split("]")[0] + ";\n"
            except :
                chunk += "return " + self.registers['eax'] + ";\n"
            return chunk

        if self.removed_canary == False:
            self.removed_canary = True

            firstCanary = NextHead(NextHead(start))
            lastCanary = PrevHead(PrevHead(end))
            self.indent += 1

            self.funcName = GetFunctionName(self.hexrayStartAddrss)
            if self.funcName == "main":
                self.func_is_main = True
                main_parameter = "int argc, const char **argv, const char **envp"
            else:
                main_parameter = ", ".join(getParam(self.funcName))
                True # 파라미터 [ebp+XX] 계산하는거 추가해야함

            chunk += "int %s(%s)\n" % (self.funcName, main_parameter)
            chunk += "{\n"
            chunk += self.hexray_opcodes(firstCanary, lastCanary)
            chunk += "}\n"
            return chunk

        if self.init_vars == False and self.var_size != 0:
            self.init_vars = True
            s = 0
            for _ in self.var_list:
                s += 1
                chunk += self.add_sourcecode("int var%s; //[bp-0x%02x]" % (s, s * 4))
            chunk += "\n"
            chunk += self.hexray_opcodes(start, end)
            return chunk

        if self.disas_list[start]['instruction'] == "mov" :
            self.movCount += 1
            if self.funcName != "main" and self.movCount <= len(getParam(self.funcName)) :
                pass
            else :
                if self.disas_list[start]['op_second'] in self.registers.keys() : # key가 있다면
                    self.disas_list[start]['op_second'] = self.registers[self.disas_list[start]['op_second']]

                # 지역 변수 부분
                if self.disas_list[start]['op_first'][0:5] == "[rbp+" :
                    print self.disas_list[start]['op_first']
                    if self.disas_list[start]['op_first'].strip("]").split("+")[1] not in self.var_list :
                        self.var_list.append(self.disas_list[start]['op_first'].strip("]").split("+")[1])
                        chunk += "int " + str(self.disas_list[start]['op_first'].strip("]").split("+")[1]) + " = " + str(self.disas_list[start]['op_second']) + ";\n"
                    else : chunk += "" + self.disas_list[start]['op_first'].strip("]").split("+")[1] + " = " + self.disas_list[start]['op_second'] + ";\n"
                    chunk += self.hexray_opcodes(NextHead(start), end)
                    return chunk
                else :
                    if "offset" in self.disas_list[start]['op_second'] :
                        self.registers[self.disas_list[start]['op_first']] = self.disas_list[start]['disas'].split(";")[1]
                    else :
                        if type(self.registers[self.disas_list[start]['op_first']]) is str and self.registers[self.disas_list[start]['op_first']][0] == "[" :
                            try :
                                chunk += self.registers[self.disas_list[start]['op_first']].split("+")[1].split("]")[0] + " = " + self.registers[self.disas_list[start]['op_first']].split("+")[1].split("]")[0] + " + " + self.disas_list[start]['op_second'].split("+")[1].split("]")[0] + ";\n"
                            except :
                                pass
                            self.registers[self.disas_list[start]['op_first']] = self.disas_list[start]['op_second']
                            chunk += self.hexray_opcodes(NextHead(start), end)
                            return chunk
                        self.registers[self.disas_list[start]['op_first']] = self.disas_list[start]['op_second']

        if self.disas_list[start]['instruction'] == "imul" :
            if "offset" in self.disas_list[start]['op_second'] :
                self.registers[self.disas_list[start]['op_first']] = self.disas_list[start]['disas'].split(";")[1]
            else :
                if type(self.registers[self.disas_list[start]['op_first']]) is str and self.registers[self.disas_list[start]['op_first']][0] == "[" :
                    chunk += self.registers[self.disas_list[start]['op_first']].split("+")[1].split("]")[0] + " = " + self.registers[self.disas_list[start]['op_first']].split("+")[1].split("]")[0] + " * " + self.disas_list[start]['op_second'].split("+")[1].split("]")[0] + ";\n"
                    chunk += self.hexray_opcodes(NextHead(start), end)
                    return chunk
                self.registers[self.disas_list[start]['op_first']] = self.disas_list[start]['op_second']


        if self.disas_list[start]['instruction'] == "sub" :
            if self.disas_list[start]['op_second'][-1] == "h" : self.disas_list[start]['op_second'] = self.disas_list[start]['op_second'][0:-1]
            self.registers[self.disas_list[start]['op_first']] = self.registers.get(self.disas_list[start]['op_first'], 0) - int(self.disas_list[start]['op_second'])

        if self.disas_list[start]['instruction'] == "add" :
            # print self.disas_list[start]['op_first'], self.disas_list[start]['op_second']
            if self.disas_list[start]['op_first'] in self.registers.keys() and self.disas_list[start]['op_second'] in self.registers.keys():
                self.registers[self.disas_list[start]['op_first']] = self.registers[self.disas_list[start]['op_second']]
            else :
                if self.disas_list[start]['op_second'][-1] == "h" : self.disas_list[start]['op_second'] = self.disas_list[start]['op_second'][0:-1]
                self.registers[self.disas_list[start]['op_first']] = self.registers.get(self.disas_list[start]['op_first'], 0) + int(self.disas_list[start]['op_second'])

        if self.disas_list[start]['instruction'] == "call" :
            fname = self.disas_list[start]['op_first']
            argu = {
                # 0 : self.registers.get('eax', 0),
                0 : self.registers.get('edi', 0),
                1 : self.registers.get('esi', 0),
                2 : self.registers.get('edx', 0),
                3 : self.registers.get('ecx', 0),
                4 : self.registers.get('r8d', 0),
                5 : self.registers.get('r9d', 0)
            }

            for i in range(0, 6) :
                for j in self.var_list :
                    if argu[i] == "[rbp+" + str(j) + "]" :
                        argu[i] = j

            if fname == "_printf" :
                chunk += fname + "(" + argu[0] + ", " + argu[1] + ");" + "\n"
            else :
                paramCount = len(getParam(fname))
                v = []
                print "JTJ"
                for i in range(0, paramCount) :
                    print argu[i]
                    v.append(str(argu[i]))
                # chunk += fname + "(" + ",".join(v) + ");" + "\n"
                self.registers['eax'] = fname + "(" + ",".join(v) + ")"
            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk



        # 어셈블리 출력
        print self.disas_list[start]['disas']

        if self.init_vars == True:
            # 지역변수가 선언된 후 ray 시작
            True

            # 함수부터 찾아서 add esp, XX로 인자갯수 파악 후 함수만 일단 싹다 소스코드로 변환하는게 좋을 것 같음
            # hexray_opcodes(start, 서브함수 시작전) + hexray_opcodes(서브함수 시작, 서브함수의 끝) + hexray_opcodes(서브함수의 끝, 함수의 끝)

        return self.hexray_opcodes(NextHead(start), end)


    # 어셈블리 코드를 disas_list에 넣고 hexray_opcodes 호출
    def disassembly(self):

        current = self.hexrayStartAddrss
        while current < self.hexrayEndAddrss:
            # ex) mov eax, [ebp+4]
            # instruction = mov
            # op_first = eax
            # op_first_value = (null) --> mov [eax+4], edx라면 4가 담길 듯
            # op_second = [ebp+4]
            # op_second_value = 4

            self.disas_list[current] = {
                'disas' : GetDisasm(current),
                'instruction' : GetMnem(current),
                'op_first' : GetOpnd(current, 0), # string
                'op_first_value' : self.unsigned2signed(GetOperandValue(current, 0)), # int
                'op_second' : GetOpnd(current, 1), # string
                'op_second_value' : self.unsigned2signed(GetOperandValue(current, 1)) # int
            }
            current = NextHead(current)


        self.source_code = self.hexray_opcodes(self.hexrayStartAddrss, self.hexrayEndAddrss)
        # try :
        #     self.source_code = self.hexray_opcodes(self.hexrayStartAddrss, self.hexrayEndAddrss)
        # except :
        #     print self.registers

        print self.registers

        return self.source_code



def getParam(fname) :

    ea = BeginEA()
    f = {}
    for funcea in Functions(SegStart(ea), SegEnd(ea)) :
        f[GetFunctionName(funcea)] = (funcea, FindFuncEnd(funcea))

    start = f[fname][0]
    end = f[fname][1]

    current = start
    disas_list = {}
    while current < end :
        disas_list[current] = {
            'disas' : GetDisasm(current),
            'instruction' : GetMnem(current),
            'op_first' : GetOpnd(current, 0),
            'op_second' : GetOpnd(current, 1),
        }

        if type(GetOperandValue(current, 0)) is int : disas_list[current]['op_first_value'] = unsigned2signed(GetOperandValue(current, 0)) # int
        else : disas_list[current]['op_first_value'] = GetOperandValue(current, 0) # int
        if type(GetOperandValue(current, 1)) is int : disas_list[current]['op_second_value'] = unsigned2signed(GetOperandValue(current, 1)) # int
        else : disas_list[current]['op_second_value'] = GetOperandValue(current, 1) # int

        current = NextHead(current)

    flag = False
    param = 0
    chk = 0
    args = []
    for k, v in disas_list.items() :
        chk += 1
        if chk == 1 : continue
        elif chk == 2 : continue
        if v['instruction'] == "mov" and v['op_first'][0:5] == "[rbp+":
            param += 1
            args.append("int " + v['op_first'].split("+")[1].split("]")[0])
            flag = True
        elif flag == True :
            break

    return args

# int32로 변환 (야매인데 잘됨)
def unsigned2signed(t):
    if t > 2147483647:
        t -= 4294967296
    return t






print "*** Hey-rays Start ***"


# print getParam("foo")


targetAddress = ScreenEA() # 현재 커서주소 반환
hr = Hexray(targetAddress)

source_code = hr.disassembly()
createFile("hexray.txt", source_code)


print "---- source code ----"
print source_code
print "---------------------"


print "*** Hey-rays End ***"
