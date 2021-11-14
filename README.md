# MakeROP
Make ROP chain building simple with rp++ output file.

Automate ROP chain creation with known good instruction file.
Instruction file line formats must match the gadget file format.
This was created with output from rp++.

Prepend 'bypass' to desired gadget line to input custom value.
Syntax: bypass 0x41414141 junk

<h1>Set input files</h1>

![image](https://user-images.githubusercontent.com/49540886/141690311-c14fc6ce-1762-42d9-941a-bb0a69e6d8ab.png)

<h1>Get ROP chain</h1>

![image](https://user-images.githubusercontent.com/49540886/141692209-bc9cc037-23ba-4768-a998-5f8590bd6a4d.png)
