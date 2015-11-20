# rtsectiontest
An Attempt to Bypass Memory Scanners By Misusing the ntdll.dll "RT" Section.

SEE WINDOWS 10 10525+ ISSUE!!!

See also branch "rtsectiontest_2"!


The rtsectiontest project attempts to trick (simple) memory/hook scanners by neither leaving any memory protection alternation nor any additional RX/RWX memory, whether the scanners are used on demand or employed inside anti cheat software.
In order to do this, it tries to place the payload code within the last 2 KB of an undocumented section "RT" of ntdll.dll in the VA space of any arbitrary non-protected (yet trusted) process, whose name may be specified in a #define statement.
The "RT" section is 4 KB in size and executable by default.

Moreover, it tries to keep a low profile while attempting to gain trusted process control by letting x64 HIPS only see the occurrence of an NtOpenProcess call. 
First time execution of arbitrary code is triggered using syscall stub hijacking in order to then force silent creation of a dedicated payload thread.
Due to the small section size as well as the required bootstrap code, any payload code should fit into 2 KB.

By elaboratedly using the Windows thread pool facility the remote code execution is now immediate and does not need
to wait anymore until a particular syscall stub is being called.

NOTE: The payload code still consists of nothing than a single "EB FE" instruction. Furthermore there is still lack of an interface for adding code in C format.

Quick edit: C interface with basic low level debug output implemented.
Detection again checked against WIN64AST for Windows 10, now only
found "NtOpenProcess(..., PROCESS_ALL_ACCESS,...)" detection, nothing further.

Code way too large to fit in 2kb of rt section.
