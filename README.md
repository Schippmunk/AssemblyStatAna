https://godbolt.org/
is where you can put in a C program and obtain Assembly output.
The tests given to us really aren't sufficient.
We still need to write a small function that turns assembly into JSON

On the project page there is a list of the order of the registers used
to pass parameters to function calls

We also need to analyze the different effects of moving stuff from reg to reg,
reg to mem etc. in program.py

Some info about the calling conventions can be found here
http://lomont.org/Math/Papers/2009/Introduction%20to%20x64%20Assembly.pdf

I use the following abbreviation vor variable names
 position -> pos
 variable -> var
 register -> reg
 paramter -> param
 recursive -> rec
 instruction -> inst
 
There are some INVALIDACCS vulnerabilities that are easy to detect, e.g.
when the shadow space between the buffer and the RBP, where there is no variable,
is overflown.
 
