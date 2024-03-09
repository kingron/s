# s

The simple, fast, powerful SYN/TCP port scanner source code

WARNNING
---
The TCP Port Scanner files which download from the 3rd internet web site might include backdoor/trojans.
Highly recommend that you download source code and recompile yourself.
If you don't want to compile it, please download s.exe from release folder, a pre-compiled executable file include yet.

How to compile
----
1. Clone/download project files.
2. Compile with [TCC](https://download.savannah.gnu.org/releases/tinycc/), recommend
    - Download tcc-0.9.27-win32-bin.zip and unzip
    - Dwonload winapi-full-for-0.9.27.zip, and overwrite include folder by zip's include folder
    - Run `tcc s.c` to build
3. Compile with Mirosoft Compiler: `cl s.c`
3. Compile with gcc: `gcc s.c -lws2_32 -lIphlpapi`

Usage
---
TCP Port Scanner V1.2 By WinEggDrop

Usage:   
`bash
s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]
`

Example: 
```bash
s TCP 12.12.12.12 12.12.12.254 80 512
s TCP 12.12.12.12/24 80 512
s TCP 12.12.12.12/24 80 512 /T8 /Save
s TCP 12.12.12.12 12.12.12.254 80 512 /HBanner
s TCP 12.12.12.12 12.12.12.254 21 512 /Banner
s TCP 12.12.12.12 1-65535 512
s TCP 12.12.12.12 12.12.12.254 21,3389,5631 512
s TCP 12.12.12.12 21,3389,5631 512
s SYN 12.12.12.12 12.12.12.254 80
s SYN 12.12.12.12 1-65535
s SYN 12.12.12.12 12.12.12.254 21,80,3389
s SYN 12.12.12.12 21,80,3389
```
