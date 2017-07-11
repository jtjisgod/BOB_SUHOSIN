#-*- coding: utf-8 -*-
#build: python 2.7

from idaapi import *
from idautils import *
import re
import json


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
    var_accessed = [] # True or False
    registers = {
        'eax' : 0, 'eax_r' : None,
        'ebx' : 0, 'ebx_r' : None,
        'ecx' : 0, 'ecx_r' : None,
        'edx' : 0, 'edx_r' : None,
        'edi' : 0, 'edi_r' : None,
        'esi' : 0, 'esi_r' : None,
        'ebp' : 0, 'ebp_r' : None,
        'esp' : 0, 'esp_r' : None,
    }
    eflags = { 'zf' : 0 } # test eax, eax 처리를 위해서

    removed_canary = False # 더미 제거상태
    init_vars = False # 지역변수 선언상태
    func_is_main = False # 일반 함수와 main함수의 구조가 약간 다르니까 이 플래그로 나중에 더미제거할 때 예외처리
    indent = 0 # 들여쓰기
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
    def parseString(self, f, l, data):
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
                self.var_size = self.disas_list[address]['op_second_value'] + 8
                size = 0
                while size < self.var_size:
                    self.var_list.append(0) # 변수를 0으로 초기화
                    self.var_accessed.append(False)
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


    # 레지스터인지 판별하는 함수
    def IsRegister(self, reg):
        reg_list = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp']
        if reg in reg_list:
            return True
        else:
            return False

    # 함수 처리
    # parameter_count가 당장은 필요없지만 push로 전달을 안할수도 있으니까
    # 장기적으로 보면 필요함!!
    def handler_function(self, start, end, parameter_count):
        chunk = ""


        # 역순으로 읽어나가면서 Call 구문 생성
        # 처음 end가 가리키는건 add esp, XX이므로 Prev해줌


        function_name = self.disas_list[end]['op_first']
        chunk += function_name + "("
        
        address = PrevHead(end)
        while address >= start:
            if self.disas_list[address]['instruction'] == 'push':
                parameter_count -= 1
                push_address = self.disas_list[address]['op_first_value']
                push_string = GetString(push_address)
                push_address_str = self.disas_list[address]['op_first']
                
                # String 탐지
                if push_string != None:
                    push_string = json.dumps(push_string).strip('"')
                    chunk += '"' + push_string + '"';
                    
                    if parameter_count != 0:
                        chunk += ', ';

                # 지역변수 푸시
                elif push_address_str.find("[ebp") != -1:
                    offset = -self.disas_list[address]['op_first_value'] / 4
                    chunk += "var%d" % offset

                # 레지스터 푸시
                elif self.IsRegister(push_address_str):
                    # 지역변수
                    if self.registers[push_address_str+"_r"] == 'ebp':
                        offset = -self.registers[push_address_str] / 4
                        print "offset is %d " % offset
                        chunk += "var%d" % offset
                        self.var_accessed[offset] = True

                #print "PushTest: " + str(push_address_str)
                
   
            address = PrevHead(address)
        chunk += ");"
        return self.add_sourcecode(chunk)

    # al, ax 같은 1~2바이트 레지스터 값을 얻어오는 함수
    def getRegisterValue(self, reg):
        l_list = ['al', 'bl', 'cl', 'dl']
        x_list = ['ax', 'bx', 'cx', 'dx']
        reg_list = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp']
        
        if reg in l_list:
            return self.registers['e'+reg[0:1]+'x'] & 0xFF
        
        if reg in x_list:
            return self.registers['e'+reg[0:1]+'x'] & 0xFFFF

        if reg in reg_list:
            return self.registers[reg]

        else:
            print "getRegisterValue:: Unknown Register !!"
            return None
        

    def childToParentRegister(self, reg):
        l_list = ['al', 'bl', 'cl', 'dl']
        x_list = ['ax', 'bx', 'cx', 'dx']
        reg_list = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp']
        
        if reg in l_list:
            return 'e'+reg[0:1]+'x'
        
        if reg in x_list:
            return 'e'+reg[0:1]+'x'

        if reg in reg_list:
            return reg

        else:
            print "childToParentRegister:: Unknown Register !!"
            return None


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

            s = 0
            for _ in self.var_list:
                s += 1
                chunk += self.add_sourcecode("int var%s; //[bp-0x%02x]" % (s, s * 4))
            chunk += "\n"
            chunk += self.hexray_opcodes(start, end)
            return chunk


        # mov 처리
        if self.disas_list[start]['instruction'] == 'mov':

            # mov [ebp-0x??], ?? 처리
            if self.disas_list[start]['op_first'].find("[ebp") != -1:
                offset = -self.disas_list[start]['op_first_value'] / 4

                if self.IsRegister(self.disas_list[start]['op_second']):
                    # mov [ebp-0x??], 레지스터
                    self.var_list[offset] = self.registers[self.disas_list[start]['op_second']]
                else:
                    # mov [ebp-0x??], 상수
                    self.var_list[offset] = self.disas_list[start]['op_second_value']
                
                # 참조한 변수는 TrueFlag설정
                self.var_accessed[offset] = True
                
                chunk += self.add_sourcecode("var%s = %d; //0x%x" % (offset, self.var_list[offset], self.var_list[offset] & 0xFFFFFFFF))
                chunk += self.hexray_opcodes(NextHead(start), end)
                return chunk

            # mov eax, [ebp-0x??] 같은거 처리
            elif self.disas_list[start]['op_second'].find("[ebp") != -1:
                offset = -self.disas_list[start]['op_second_value'] / 4
                target_register = self.disas_list[start]['op_first']
                self.registers[target_register] = self.var_list[offset]

                chunk += self.hexray_opcodes(NextHead(start), end)
                return chunk

            # mov eax, ecx 같은거 처리
            elif self.IsRegister(self.disas_list[start]['op_second']):
                target_register = self.disas_list[start]['op_first']
                victim_register = self.disas_list[start]['op_second']

                self.registers[target_register] = self.registers[victim_register]
                self.registers[target_register + "_r"] = None
                chunk += self.hexray_opcodes(NextHead(start), end)
                return chunk

            elif self.disas_list[start]['op_second'][0:1] == '[' and self.disas_list[start]['op_second'][4:5] == ']':
                target_register = self.disas_list[start]['op_first']
                victim_register = self.disas_list[start]['op_second'][1:4]
                
                print self.registers[victim_register+"_r"]
                print self.registers[victim_register]
                chunk += self.hexray_opcodes(NextHead(start), end)
                return chunk

            # mov eax, 상수 같은거 처리
            elif self.disas_list[start]['op_second'] == str(self.disas_list[start]['op_second_value']):
                target_register = self.disas_list[start]['op_first']

                self.registers[target_register] = self.disas_list[start]['op_second_value']
                self.registers[target_register + "_r"] = None
                chunk += self.hexray_opcodes(NextHead(start), end)
                return chunk


            
            else:
                print "Unknown Mov:: %s" % self.disas_list[start]['disas']

        # not 처리
        if self.disas_list[start]['instruction'] == 'not':
            target_register = self.disas_list[start]['op_first']
            self.registers[target_register] = ~self.registers[target_register]
            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk

        # test 처리
        if self.disas_list[start]['instruction'] == 'test':
            target_register = self.disas_list[start]['op_first']
            victim_register = self.disas_list[start]['op_second']
            if target_register == victim_register:
                if self.registers[target_register] != 0:
                    self.eflags['zf'] = 1
                else:
                    self.eflags['zf'] = 0
            else:
                print "Unknown test:: %s" % self.disas_list[start]['disas']
            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk

        # setz 처리
        if self.disas_list[start]['instruction'] == 'setz':
            target_register = self.childToParentRegister(self.disas_list[start]['op_first'])
            self.registers[target_register] = self.eflags['zf']
            print "Set ZF to %d -> %s" % (self.eflags['zf'], target_register)
            
            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk

            
        # sub 처리(함수 처리용)
        if self.init_vars == True and self.disas_list[start]['instruction'] == 'sub':
            # sub esp, XX(sub_esp_value)가 들어오면 함수 시작
            sub_esp_value = self.disas_list[start]['op_second_value']
            start = NextHead(start)
            
            func_start_address = start
            while 1:
                if (self.disas_list[start]['instruction'] == 'add' and
                    self.disas_list[start]['op_first'] == 'esp'):
                    break
                
                start = NextHead(start)

            # func_start_address를 push가 나타날 때 까지 뒤로 더 땡긴다
            original_func_start_address = func_start_address
            while 1:
                if self.disas_list[func_start_address]['instruction'] == 'push':
                    break

                func_start_address = NextHead(func_start_address)

            chunk += self.hexray_opcodes(original_func_start_address, func_start_address)
            
            add_esp_value = self.disas_list[start]['op_second_value']
            func_end_address = PrevHead(start)

            # 이렇게하면 파라미터 갯수가 나옴!
            parameter_count = (add_esp_value - sub_esp_value) / 4
            chunk += self.handler_function(func_start_address, func_end_address, parameter_count)
            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk

        # lea 처리
        if self.disas_list[start]['instruction'] == 'lea':
            target_register = self.disas_list[start]['op_first']
            victim_register = self.disas_list[start]['op_second'][1:4]
            if victim_register != 'ebp' and self.registers[victim_register + "_r"] == 'ebp':
                self.registers[target_register] = self.registers[victim_register] + self.disas_list[start]['op_second_value']
                self.registers[target_register + "_r"] = 'ebp'
                chunk += self.hexray_opcodes(NextHead(start), end)
                return chunk

            
            #print "victim_register is %s" % victim_register

            # 레지스터 변수 설정
            self.registers[target_register] = self.disas_list[start]['op_second_value']
            self.registers[target_register + "_r"] = victim_register
            #print "lea:: %s register to %d" % (target_register, self.disas_list[start]['op_second_value'])
            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk

        # add 처리
        if self.disas_list[start]['instruction'] == 'add':
            target_register = self.disas_list[start]['op_first']
            victim_register = self.disas_list[start]['op_second']
            
            if self.IsRegister(victim_register):
                # 레지스터끼리 더하는 연산
                self.registers[target_register] += self.registers[victim_register]
                #print "add:: %s register to %d" % (target_register, self.registers[target_register])
            else:
                # 레지스터에 상수 더하기
                self.registers[target_register] += self.disas_list[start]['op_second_value']
                #print "add:: %s register to %d" % (target_register, self.disas_list[start]['op_second_value'])


            chunk += self.hexray_opcodes(NextHead(start), end)
            return chunk
        

        # 남은 어셈블리 출력
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
