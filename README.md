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

![image](https://user-images.githubusercontent.com/49540886/141690311-c14fc6ce-1762-42d9-941a-bb0a69e6d8ab.png)

<h3>Example of desired gadgets file</h3>

![image](https://user-images.githubusercontent.com/49540886/141692505-afc23af6-4e44-44da-ae8f-48fa304ae361.png)

<h3>Set bad chars</h3>

![image](https://user-images.githubusercontent.com/49540886/141701335-b92b42c0-548e-40fd-8995-ced5f01596dc.png)

<h1>Get ROP chain</h1>

![image](https://user-images.githubusercontent.com/49540886/141692209-bc9cc037-23ba-4768-a998-5f8590bd6a4d.png)
