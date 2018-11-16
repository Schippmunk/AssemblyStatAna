Call the program as follows:
python3.7 bo-analyser.py "testfile.json"

NOTE: python3.7 is required, 3.6 is not good enough






IGNORE THIS, THESE ARE JUST SOME NOTES

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

Info about x64 intel stack layout
https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/

Powerpoint presentation explaining function calls in x86
 https://www.cs.princeton.edu/courses/archive/spr11/cos217/lectures/15AssemblyFunctions.pdf
