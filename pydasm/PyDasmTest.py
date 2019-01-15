import pydasm

def Test1():
	buffer = b'\x90\x31\xc9\x31\xca\x31\xcb'
	tArr = ['nop', 'xor ecx,ecx', 'xor edx,ecx', 'xor ebx,ecx']

	return DAsmLoop(buffer, tArr)
	
def Test2():
	buffer = 'abcd'
	tArr = []

	try:
		DAsmLoop(buffer, tArr)
	except:
		pass
	return True
	
def Test3():
	buffer = [1, 2, 3, 4]
	tArr = []

	try:
		DAsmLoop(buffer, tArr)
	except:
		pass
	return True
	
def Test4():
	buffer = b'zzzzzzzzzzzzzzzzzzzzzz'
	tArr = []

	return DAsmLoop(buffer, tArr)
	
def Test5():
	I = pydasm.Instruction()
	return True
	
def Test6():
	D = pydasm.DAsm()
	return True
	
def Test7():
	I = pydasm.Inst()
	return True
	
def Test8():
	O = pydasm.Operand()
	return True
	
def DAsmLoop(buf, tArr):
	offset = 0
	j = 0
	while offset < len(buf):
		D = pydasm.DAsm()
		i = D.get_instruction(buf[offset:], pydasm.MODE_32)
		if not i:
			return False
		s = D.get_instruction_string(i, pydasm.FORMAT_INTEL, 0).strip()
		if len(tArr) > 0 and s != tArr[j % len(tArr)]:
			print('Failed! {:s} != {:s}'.format(s, tArr[j % len(tArr)]))
			return False
		offset += i.length
		j += 1
	return True
	
def TestLooper(n, Testj):
	print('TEST ', Testj.__name__, '\t', end='')
	okay = True
	for i in range(n):
		okay &= Testj()
		if not okay:
			print('FAIL')
			break
	print('PASS')
	
		
if __name__ == "__main__":
	for Ti in [Test1, Test2, Test3, Test4, Test5, Test6, Test7, Test8]:
		TestLooper(59999, Ti)