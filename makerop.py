#	Author: Mason Palma
#	Purpose: Make easy ropchains from desired instructions using RP++ gadget output file(s).
#

import sys
import random
import struct


class makeROP:

	def __init__(self):

		self.gadget_files = [] #File(s) of Gadgets, written with rp++ output
		self.desired_file = '' #Desired gadgets should match the format in gadget file

		#	Ensure match of desired lines to gadget file
		#	Example: 	If gadget desired is 'mov esi, esi '
		#			make sure desired line is 'mov esi, esi ' not 'mov esi,esi' or any other deviation

		self.all_gadgets = []
		self.desired_gadgets = []
		self.bad_chars = []
		self.mod_base = 0x0
		self.ASLR = False

		#	Use address from leaked memory base of gadget_file
		#	use multiple files, must be in same order as in gadget_files
		#
		#	Ex.		gadget_files = [('gadget_file1', 0x10000000), ('gadget_file2', 0x20000000)]
		#			set_base([leaked_address_of_file1, leaked_address_of_file2])


	def set_desired_gadgets_file(self, file):
		global desired_gadgets

		self.desired_gadgets = ''

		with open(file) as f:
			self.set_desired_gadgets(f.readlines())

	def set_gadget_files(self, file):
		global gadget_files

		if file:
			self.gadget_files = file

	def set_bad_chars(self, bc):
		global bad_chars
		self.bad_chars = bc

	def set_desired_gadgets(self, dg):
		global desired_file
		self.desired_file = dg

	def set_ASLR(self, flag):
		global ASLR
		self.ASLR = flag

	def set_base(self, mb):
		global mod_base
		global gadget_files

		if len(mb) != len(self.gadget_files):
			print('Supply the correct amount of preferred base addresses.')
			print(f'The expected number was {len(self.gadget_files)}\nReceived {len(mb)}.')

		else:
			self.mod_base = mb
			for i in range(0, len(self.mod_base)):
				self.gadget_files[i] = (self.gadget_files[i][0], self.gadget_files[i][1], self.mod_base[i])


	def check_bad_chars(self, addr):
		global bad_chars
		
		addr = int(addr, 0)
		test = struct.unpack('4B', struct.pack('>I', addr))
		found_bad_flag = False
		for bad in self.bad_chars:
			if bad in test:
				found_bad_flag = True

		if found_bad_flag == False:
			return False
		if found_bad_flag == True:
			return True

		
	def populate_gadgets_ASLR(self):
		global gadget_files
		global desired_file

		#Populate all_gadgets from usable gadgets in gadget file
		#Tuple for ASLR bypass through offset
		for gadget_file in self.gadget_files:
			for line in open(gadget_file[0], 'r').readlines():
				if "0x" in line:
					if not self.check_bad_chars(line.split(':')[0]):
						self.all_gadgets.append((line, gadget_file[1], gadget_file[2]))

		

		#Populate desired_gadgets from instruction file
		for line in self.desired_file:
			l = line.lstrip()
			result = l.rstrip()
			self.desired_gadgets.append(result)


	def populate_gadgets(self):
		global gadget_files
		global all_gadgets
		global desired_file
		global desired_gadgets
		
		#Populate all_gadgets from usable gadgets in gadget file
		for gadget_file in self.gadget_files:
			for line in open(gadget_file[0], 'r').readlines():
				if "0x" in line:
					if not self.check_bad_chars(line.split(':')[0]):
							self.all_gadgets.append((line, 0x0))

		

		#Populate desired_gadgets from instruction file
		for line in self.desired_file:
			l = line.lstrip()
			result = l.rstrip()
			self.desired_gadgets.append(result)


	def populate(self):
		global ASLR

		if self.ASLR is False: 
			self.populate_gadgets()
			print('\nASLR bypass mode turned off\n')

		elif self.ASLR is True:
			self.populate_gadgets_ASLR()
			print('\nASLR bypass mode turned on\n')


	#Find matching gadget
	def find_this_gadget(self, query):
		global ASLR
		global all_gadgets

		if 'bypass' in query or '#' in query:
			return (query, 0x0, 0x0)

		matches = []
		#	This value can be anything larger than expected output
		smallest_match = 1000
		result_matches = []
		#	Iterate through all gadgets to find match
		for gadget in self.all_gadgets:
			if len(gadget[0].split(':')) == 2:
				addr, other = gadget[0].split(':')
				if len(query.split(' ')) != 1:
					if query in other:
						if 'call' not in other and 'jmp' not in other and 'and' not in other and 'leave' not in other:

							if self.ASLR is True:
								matches.append((gadget[0].strip(), gadget[1], gadget[2]))

							elif self.ASLR is False:
								matches.append((gadget[0].strip(), gadget[1]))

							if len(gadget[0]) < smallest_match:
								smallest_match = len(gadget[0])
		#	If no match found
		if len(matches) == 0:
			return "[*] Could not find gadget for %s" % query

		#	If matches found
		#	Iterate through matches to find smallest match/gadget
		for match in matches:
			if len(match[0]) < smallest_match:
				result_matches.append(match)
		
		#	Return single and smallest match. Switch return statements for random return
		#	Leave static match return for exploit development
		#return result_matches[random.randint(0, len(result_matches)-1)]
		return result_matches[0]


	#	Build ROP chain
	def build_ROP(self):
		global ASLR
		global desired_gadgets

		self.populate()

		ropchain = []

		#	Output and flag returned if used as module
		output = b""
		error_flag = False
		
		for dg in self.desired_gadgets:
			result = self.find_this_gadget(dg)
			ropchain.append(result)

		#	Pound to include comment in string output
		pound = '#'

		print('ropchain = b"" %s Initialize ropchain' % pound)
		linenumber = 1

		for g in ropchain:

			if "bypass" in g[0]:
				addr = g[0].split(' ')[1]
				print("ropchain += pack('<L', (%s)) %s %s [Line: %d]" % (addr, pound, g, linenumber))
				try:
					output += struct.pack('<L', int(addr, 0))
				except:
					error_flag = True
					continue

			elif "#" in g[0]:
				print('\n' + g[0] + '\n')

			elif "Could not find gadget for" not in g[:]:
				if self.ASLR:
					base = int(g[1])
					addr = g[0].split(':')[0] 
					addr = int(addr, 0) - base
					addr = addr + g[2]
					addr = hex(addr)

				elif self.ASLR is False:
					addr = g[0].split(':')[0]

				print("ropchain += pack('<L', (%s)) %s %s [Line: %d]" % (addr, pound, g[0], linenumber))
				
				try:
					output += struct.pack('<L', int(addr, 0))
				
				except:
					print(type(addr))
					error_flag = True
					continue

			else:
				print("ropchain += pack('<L', (?)) %s %s [Line: %d]" % (pound, g[0], linenumber))
				error_flag = True

			linenumber+=1
			
		#Clear gadgets to make buildROP reusable
		self.desired_gadgets = []

		print('')

		if error_flag == False:
			return output, True
		elif error_flag == True:
			return output, False


if __name__ == '__main__':
	import makeROP_test
	import argparse
	
	p = argparse.ArgumentParser()
	p.add_argument('-gf', '--gadget_file', nargs='+', type=str, help='RP++ gadget output file(s). Pass as tuple with preferred base addr.')
	p.add_argument('-dg', '--desired_gadgets', type=str, help='Desired gadgets file.')
	p.add_argument('-bc', '--bad_chars', nargs='*', type=str, help='Bad characters.')
	p.add_argument('-aslr', '--ASLR', type=str, help='Default False. Set True to rebase gadgets.')
	p.add_argument('-ba', '--base_addr', nargs='*',type=int, help='New base address of module-- only required if rebasing.')

	args = p.parse_args()


	if args.gadget_file and args.desired_gadgets:
		a = makeROP_test.makeROP()
		a.set_gadget_files([(args.gadget_file[0], int(args.gadget_file[1], 0))])

		if args.ASLR and args.base_addr:
			if 'true' in args.ASLR or 'True' in args.ASLR:
				a.set_ASLR(True)
				
			elif 'false' in args.ASLR or 'False' in args.ASLR:
				a.set_ASLR(False)

			a.set_base(args.base_addr)
		
		a.set_desired_gadgets_file(args.desired_gadgets)

		if args.bad_chars:
			a.set_bad_chars(args.bad_chars)

		b = a.build_ROP()

		if b[1] is True and b[0] != '':
			print('Successful ROPchain created!\n')
			print(b[0])
		else:
			print('Something went wrong..')
			print(b[0])
