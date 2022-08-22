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

```python
import MakeROP

a = MakeROP.makeROP()

a.set_gadget_files([('FILENAME', 0xPREFBASEADDR)])
a.set_bad_chars([0x00, 0x09, 0x0A, ...])

a.set_ASLR(True)
#IF ASLR, set new base address
a.set_base([0xNEWADDRESS])

a.set_desired_gadgets(
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

b = a.build_ROP()

print(b)
```

![image](https://user-images.githubusercontent.com/49540886/147863456-e99314e3-ccf1-4d48-81eb-43b91d7ec1d6.png)

![image](https://user-images.githubusercontent.com/49540886/147863460-dd26e8bb-8ffb-4106-b01b-75fd2f432e8f.png)
