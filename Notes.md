https://godbolt.org/
is where you can put in a C program and obtain Assembly output.
The tests given to us really aren't sufficient.
We still need to write a small function that turns assembly into JSON


If the program is compliled with x86-64 gcc 8.2 then strcpy gets its parameters from rsi and rdi

Now, write a function that works as a table:
For each register, at each position in the program,
know what is in there

I use the following abbreviation vor variable names
 position -> pos
 variable -> var
 register -> reg
 paramter -> param
 recursive -> rec
 instruction -> instr
 

fgets seems to get its parameters from the following registers:
param 1 / buffer from rax
param 2 / inputlength from esi 