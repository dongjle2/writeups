## baby

#### First, I looked into the executable using binary ninja.

![flow](https://github.com/dongjle2/writeups/blob/main/level3/autorev/baby/baby_1.JPG)



#### The image shows some complex stuffs but no need to worry because I just let angr work on it.

#### More important thing is for the challenge, the objective is to get the correct license. 

#### I used the following 2 facts.

1. Tell angr reach to address 0x40187d, which is the desired address when correct license is given.

2. Tell angr that the license is length of 0x20 string.


[script](https://github.com/dongjle2/writeups/blob/main/level3/autorev/baby/sol.py)
