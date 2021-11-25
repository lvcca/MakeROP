#	Author: Mason Palma
#	Purpose: Make easy ropchains from desired instructions
#

import sys
import random
import struct

gadget_files = ['csncdav6_gadgets.txt', 'csmtpav6_gadgets.txt', 'snfs_gadgets.txt', 'csftpav6_gadgets.txt'] #File(s) of Gadgets, written with rp++ output
desired_file = open('desired_gadgets.txt', 'r') #Desired gadgets should match the format in gadget file

#ensure match of desired lines to gadget file
#Example: 	If gadget desired is 'mov esi, esi '
#		make sure desired line is 'mov esi, esi ' not 'mov esi,esi' or any other deviation

all_gadgets = []
desired_gadgets = []
bad_chars = [ 0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20 ]

def check_bad_chars(addr):
	global bad_chars
	#print(addr)
	addr = int(addr, 0)
	test = struct.unpack('4B', struct.pack('>I', addr))
	found_bad_flag = False
	for bad in bad_chars:
		if bad in test:
			#print('Bad char %d found in %s' % (bad, test))
			found_bad_flag = True

	if found_bad_flag == False:
		return False
	if found_bad_flag == True:
		return True

#Populate all_gadgets from usable gadgets in gadget file
for gadget_file in gadget_files:
	for line in open(gadget_file, 'r').readlines():
		if "0x" in line:
			if not check_bad_chars(line.split(':')[0]):
				all_gadgets.append(line)

#Populate desired_gadgets from instruction file
for line in desired_file.readlines():
	l = line.lstrip()
	result = l.rstrip()
	desired_gadgets.append(result)

#Find matching gadget
def find_this_gadget(query):
	if 'bypass' in query or '#' in query:
		return query

	matches = []
	#this value can be anything larger than expected output
	smallest_match = 1000
	result_matches = []
	#iterate through all gadgets to find match
	for gadget in all_gadgets:
		if len(gadget.split(':')) == 2:
			addr, other = gadget.split(':')
			if len(query.split(' ')) != 1:
				if query in other:
					if 'call' not in other and 'jmp' not in other and 'and' not in other and 'leave' not in other:
						matches.append(gadget.strip())
						if len(gadget) < smallest_match:
							smallest_match = len(gadget)
	#if no match found
	if len(matches) == 0:
		return "[*] Could not find gadget for %s" % query

	#if match found
	#iterate through match to find smallest gadget
	for match in matches:
		if len(match) < smallest_match:
			result_matches.append(match)
	#return match
	#print('[*] Found %d matches for "%s."' % (len(matches), query))
	return result_matches[random.randint(0, len(result_matches)-1)]


def build_ROP():
	#Build ROP chain
	ropchain = []
	#For run as module
	output = b""
	error_flag = False

	global desired_gadgets
	for dg in desired_gadgets:
		result = find_this_gadget(dg)
		ropchain.append(result)

	#Pound to include comment in string output
	pound = '#'

	print('ropchain = b"" %s Initialize ropchain' % pound)
	linenumber = 1
	for g in ropchain:
		if "bypass" in g:
			addr = g.split(' ')[1]
			print("ropchain += pack('<L', (%s)) %s %s [Line: %d]" % (addr, pound, g, linenumber))
			try:
				output += struct.pack('<L', int(addr, 0))
			except:
				error_flag = True
				continue

		elif "#" in g:
			print('\n' + g + '\n')
		elif "Could not find gadget for " not in g:
			addr = g.split(':')[0]
			print("ropchain += pack('<L', (%s)) %s %s [Line: %d]" % (addr, pound, g, linenumber))
			try:
				output += struct.pack('<L', int(addr, 0)) 
			except:
				print(type(addr))
				error_flag = True
				continue
		else:
			print("ropchain += pack('<L', (?)) %s %s [Line: %d]" % (pound, g, linenumber))
			error_flag = True

		linenumber+=1

	if error_flag == False:
		return output, True
	elif error_flag == True:
		return output, False


# --- Find Matches ---

# Write Registers
# Primary Storage Register
# Secondary Storage Register
# Instruction Pointer
# Incr Instruction Pointer
# Xchg registers

registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
write_match = []
primary_storage_match = []
secondary_storage_match = []
instruction_pointer_match = []
increment_instruction_match = []
single_pop_match = []
add_match = []
sub_match = []
neg_match = []

def find_reg(search, search_type):
	global registers
	match = []
	good_registers = []
	for dst_reg in registers:
		for src_reg in registers:
			do_search = search % (dst_reg, src_reg)
			check = find_this_gadget(do_search)
			if '[*]' not in check:
				print('[*] %s match -- %s' % (search_type, check.split(':')[1].lstrip().split('(')[0]))
				match.append(check)
				good_registers.append([dst_reg, src_reg])
	return match, good_registers

def find_instruction_pointer():
	match = []
	registers = ['esp', 'ebp']
	good_registers = []
	for reg in registers:
		search = 'push %s ; ret' % reg
		check = find_this_gadget(search)
		if '[*]' not in check:
			try:
				print('[*] Psuedo instruction pointer -- ' + check.split(':')[1].split('(')[0])
				match.append(check)
				good_registers.append(reg)
			except:
				print(check)
				continue
	return match, good_registers

def find_single_pop():
	match = []
	global registers
	for reg in registers:
		search = "pop %s ; ret" % reg
		check = find_this_gadget(search)
		if '[*]' not in check:
			try:
				print('[*] Single pop -- ' + check.split(':')[1].split('(')[0])
				match.append(check)
			except:
				print(check)
				continue
	return match

def find_inc():
	global registers
	match = []
	for reg in registers:
		search = 'inc %s ; ret' % reg
		check = find_this_gadget(search)
		if '[*]' not in check:
			print('[*] Inc -- %s' + check.split(':')[1].split('(')[0])
			match.append(check)
	return match

def find_reg_single(query, searchtype):
	match = []
	global registers
	for reg in registers:
		search = query % reg
		check = find_this_gadget(search)
		if '[*]' not in check:
			try:
				print('[*] %s -- %s' % (searchtype,check.split(':')[1].split('(')[0]))
				match.append(check)
			except:
				print(check)
				continue
	return match

def get_matches():
	#Get matches for the following instructions
	write_match, write_regs = find_reg('mov dword [%s], %s ; ret', 'Patch')
	primary_storage_match, storage_regs = find_reg('mov %s, %s ; ', 'Move')
	instruction_pointer_match, ip_regs = find_instruction_pointer()
	secondary_storage_match, secondary_regs = find_reg('push %s ; pop %s ', 'Push')
	single_pop_match = find_single_pop()
	xchg_match, xchg_regs = find_reg('xchg %s, %s ; ret', 'Xchg')
	add_match, add_regs = find_reg('add %s, %s ; ret', 'Add')
	sub_match, sub_regs = find_reg('sub %s, %s ; ret', 'Sub')
	neg_match, neg_regs = find_reg('neg %s, %s ;', 'Neg')
	inc_match = find_inc()
	mov_esp_match = find_reg_single('xor %s, esp', 'XOR')
	push_matches = find_reg_single('push %s ; ', 'Push')
	stack_moves = find_reg_single('mov  %s, esp', 'ESP')

if __name__ == '__main__':

	if len(sys.argv) > 1:

		if 'ropchain' in sys.argv[1]:
			build_ROP()
		elif 'matches' in sys.argv[1]:
			get_matches()
	else:
		print('[*] -- Invalid Console Syntax --')
		print('[*] To print valid matches set in get_matches() use matches')
		print('[*] To print ROPchain from gadget_file(s) and desired_gadgets file use ropchain.')
		print("[*] Usage: python3 makeROP.py \'ropchain\'")
		print("[*] Usage: python3 makeROP.py \'matches\'")
