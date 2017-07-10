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
    source_code = ""
    disas_list = {}
    var_size = 0
    var_list = []
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

    # 마지막 더미 제거: mov ???, [ebp-0x0C] --> ???는 eax이거나 ecx일듯
    def getLastCanary(self, lastCanaryAddress):
        address = PrevHead(lastCanaryAddress)
        while 1:
            if (self.disas_list[address]['instruction'] == 'mov' and
                self.disas_list[address]['op_second'].find("[ebp") != -1 and
                self.disas_list[address]['op_second_value'] == -0x0C):
                break
            
            address = PrevHead(address)
        return address

    # 처음 더미 제거: xor eax, eax
    def getFirstCanary(self, firstCanaryAddress):
        address = firstCanaryAddress
        while 1:
            # sub esp, 0x?? -> 지역변수 크기를 얻어옴
            if (self.disas_list[address]['instruction'] == 'sub' and
                self.disas_list[address]['op_first'] == 'esp'):
                self.var_size = self.disas_list[address]['op_second_value']
                size = 4 # ebp-4는 변수에서 제외
                while size < self.var_size:
                    self.var_list.append(size / 4)
                    size += 4
            
            if (self.disas_list[address]['instruction'] == 'xor' and
                self.disas_list[address]['op_first'] == 'eax'):
                break
            
            address = NextHead(address)
        return NextHead(address)

    # 인던트 추가해서 반환
    def add_sourcecode(self, buf):
        chunk = ""
        for x in range(0, self.indent):
            chunk += "    "
        chunk += buf
        chunk += "\n"
        return chunk
        

    # 소스코드 생성하는 부분 (재귀함수)
    def hexray_opcodes(self, start, end):
        chunk = ""
        if start == end:
            return chunk

        if self.removed_canary == False:
            self.removed_canary = True
            
            firstCanary = self.getFirstCanary(start)
            lastCanary = self.getLastCanary(end)
            self.indent += 1

            self.funcName = GetFunctionName(self.hexrayStartAddrss)
            if self.funcName == "main":
                self.func_is_main = True
                main_parameter = "int argc, const char **argv, const char **envp"
            else:
                True # 파라미터 [ebp+XX] 계산하는거 추가해야함
                
            chunk += "int %s(%s)\n" % (self.funcName, main_parameter)
            chunk += "{\n"
            chunk += self.hexray_opcodes(firstCanary, lastCanary)
            chunk += "}\n"
            return chunk


        if self.init_vars == False and self.var_size != 0:
            self.init_vars = True

            for x in self.var_list:
                chunk += self.add_sourcecode("int var%s; //[bp-0x%x]" % (x, (x + 1) * 4))
            chunk += "\n"
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
        return self.source_code


print "*** Hey-rays Start ***"

targetAddress = ScreenEA() # 현재 커서주소 반환
hr = Hexray(targetAddress)

source_code = hr.disassembly()
createFile("hexray.txt", source_code)


print "---- source code ----"
print source_code
print "---------------------"


print "*** Hey-rays End ***"
