## sample / auto

First, when I used decompiler, I couldn't find big difference from the `baby` challenge so
I tried with same logic that I used for `baby` challenge. But I experienced all the following scenarios,

1) it took forever
2) it gave me wrong answer
3) it was using too much resources and the machine crashes

The problem was I was only looking at C code and since the executable was using ROP,
the decompiler couldn't generate valid C code. I should have looked into assembly code to catch it.

Overall, I relied heavily on AI to solve this challenge, especially, google gemini 2.5 Pro was really helpful.

The main logic is that I used hook/simProcedure to replace `getline` function and it worked. For angr to symbolically execute the complex `getline` function, it takes a long time and it's error-prone.
The hook function is called instead of `getline` function and it skips complex, symbolic executions for `getline` function.

For all 100 `auto` challenges, it's basically the same logic and it worked.

[sample](https://github.com/dongjle2/writeups/blob/main/level3/autorev/sample_and_auto/sample_sol.py)

[auto](https://github.com/dongjle2/writeups/blob/main/level3/autorev/sample_and_auto/auto_sol.py)