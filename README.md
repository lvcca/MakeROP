# MakeROP
Make ROP chain building simple with rp++ output file.

Automate ROP chain creation with known good instruction file.
Instruction file line formats must match the gadget file format.
Gadget returned is smallest sized match.
This was created with output from rp++.

Prepend 'bypass' to desired gadget line to input custom value.
<i>Syntax: bypass 0x41414141 junk</i>

Include comments by prepending '#' to line in desired gadgets file.
<i>Syntax: #This is comment</i>

<h1>Set input files</h1>

![image](https://user-images.githubusercontent.com/49540886/141837395-4568b608-b11d-4ac8-8b8d-27461c8c3a8e.png)

<h3>Example of desired gadgets file</h3>

![image](https://user-images.githubusercontent.com/49540886/141815435-b1520470-592c-4a22-9647-11bf091c49c4.png)

<h3>Set bad chars</h3>

![image](https://user-images.githubusercontent.com/49540886/141701335-b92b42c0-548e-40fd-8995-ced5f01596dc.png)

<h1>Get ROP chain</h1>

![image](https://user-images.githubusercontent.com/49540886/141815402-dc2389a4-56c0-4d84-8536-93bab0625827.png)

<h1>Get Matched gadgets</h1>

![image](https://user-images.githubusercontent.com/49540886/143503289-0d08776a-0e35-4a5e-9f14-a4bb912acbe9.png)

<h1>Import as module</h1>

![image](https://user-images.githubusercontent.com/49540886/143503365-78801222-08bd-4ef4-a211-7228573c2e29.png)

returns (b'MATCHED_ROPCHAIN', errors_flag)
if True: no errors

![image](https://user-images.githubusercontent.com/49540886/143503425-8413b488-9c8f-427a-8901-2fbaa157292f.png)
