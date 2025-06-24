## baby

#### First, I looked into the executable using binary ninja.

![flow](https://github.com/dongjle2/writeups/level3/autorev/baby/baby_1.JPG)

#### From the image, I found that the objective is to get the correct license. 

#### Since the flow is very simple, I will use the following 2 facts.
1. Tell angr reach to address 0x40187d, which is the desired address when correct license is given.


2. Tell angr that the license is length of 0x20 string.

[script](https://github.com/dongjle2/writeups/blob/main/dongjun_baby_sol.md/sol.py)
