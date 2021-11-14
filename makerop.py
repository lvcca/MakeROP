#       Author: Mason Palma
#       Purpose: Make easy ropchains from desired instructions
#

import random

gadget_file = open('csftpav6_gadgets.txt') #File of Gadgets, written with rp++ output
desired_file = open('desired_gadgets.txt') #Desired gadgets should match the format in gadget file

#ensure match of desired lines to gadget file
#Example:       If gadget desired is 'mov esi, esi '
#               make sure desired line is 'mov esi, esi ' not 'mov esi,esi' or any other deviation

all_gadgets = []
desired_gadgets = []

#Populate all_gadgets from usable gadgets in gadget file
for line in gadget_file.readlines():
        if "0x" in line:
                all_gadgets.append(line)

#Populate desired_gadgets from instruction file
for line in desired_file.readlines():
        l = line.lstrip()
        result = l.rstrip()
        desired_gadgets.append(result)

#Find matching gadget
def find_this_gadget(query):
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

#Build ROP chain
ropchain = []
for dg in desired_gadgets:
        result = find_this_gadget(dg)
        ropchain.append(result)

#Pound to include comment in string output
pound = '#'

print('ropchain = b"" %s Initialize ropchain' % pound)

for g in ropchain:
        if "Could not find gadget for " not in g:
                print("ropchain += pack('<L', (%s)) %s %s" % (g.split(':')[0], pound, g))
        else:
                print("ropchain += pack('<L', (?)) %s %s" % (pound, g))
