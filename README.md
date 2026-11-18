# MakeROP
Make ROP chain building simple with rp++ output file.

Automate ROP chain creation with known good instruction list of strings.
Instructions format must match the gadget file format.
Gadget returned is smallest sized match.
This was created with output from rp++.

Prepend 'bypass' to desired gadget line to input custom value.
<i>Syntax: bypass 0x41414141 junk</i>

Include comments by prepending '#' to line in desired gadgets file.
<i>Syntax: #This is comment</i>

### from example.py

```python
from MakeROP import MakeROP

_makeROP = MakeROP()

_makeROP.set_gadget_files([('./node_gadgets.txt', 0x10000000)])

_makeROP.set_bad_chars([0x00, 0x09, 0x0A])

_makeROP.set_ASLR(True)
#IF ASLR, set new base address
_makeROP.set_base([1145311796])

_makeROP.set_desired_gadgets(
	[
	'mov eax, esi; pop esi; ret',
	'bypass 0x42424242 junk',
	'pop ecx ; ret',
	'bypass 0x88888888 for shellcode',
	'add eax, ecx ; ret',
	'bypass 0x77777878 junk',
	'add eax, ecx ; ret',
	'mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010',
	'bypass 0x41414141 junk'])

_builtROP = _makeROP.build_ROP()

print(_builtROP)
```
