# s
The simple, fast, powerful SYN/TCP port scanner source code

WARNNING
=============
The TCP Port Scanner files which download from the 3rd internet web site might include backdoor/trojans.
Highly recommend that you download source code and recompile yourself.
If you don't want to compile it, please download s.exe from release folder, a pre-compiled executable file include yet.

How to compile
=============
1. Please clone/download project files.
2. Open project by Visual Studio 2015, C++ & MFC components should be installed.

Usage
=============
TCP Port Scanner V1.2 By WinEggDrop

Usage:   s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]
Example: s TCP 12.12.12.12 12.12.12.254 80 512
Example: s TCP 12.12.12.12/24 80 512
Example: s TCP 12.12.12.12/24 80 512 /T8 /Save
Example: s TCP 12.12.12.12 12.12.12.254 80 512 /HBanner
Example: s TCP 12.12.12.12 12.12.12.254 21 512 /Banner
Example: s TCP 12.12.12.12 1-65535 512
Example: s TCP 12.12.12.12 12.12.12.254 21,3389,5631 512
Example: s TCP 12.12.12.12 21,3389,5631 512
Example: s SYN 12.12.12.12 12.12.12.254 80
Example: s SYN 12.12.12.12 1-65535
Example: s SYN 12.12.12.12 12.12.12.254 21,80,3389
Example: s SYN 12.12.12.12 21,80,3389

