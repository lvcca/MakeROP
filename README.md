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

![image](https://user-images.githubusercontent.com/49540886/147863456-e99314e3-ccf1-4d48-81eb-43b91d7ec1d6.png)

![image](https://user-images.githubusercontent.com/49540886/147863460-dd26e8bb-8ffb-4106-b01b-75fd2f432e8f.png)
