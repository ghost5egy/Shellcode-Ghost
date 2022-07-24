# Shellcode-Ghost

usage :<br />
python3 shellcoder-evad.py -s msfvenomshellcode.bin -c  -xor xorkey -xorf -t template file.cpp

compile on Linux :<br />
x86_64-w64-mingw32-g++ -shared result.cpp -o loader.dll
<br />
x86_64-w64-mingw32-g++ result.cpp -o loader.exe
