## Intro
This simple Windows debugger, implemented in C/C++, operates in command-line mode. It offers a range of debugging functionalities accessible through the following commands:
Id|Function|Command|Argument 1| Argument 2| Argument 3
---|---|---|---|---|---
1|step into| t
2|step over|p
3| run|g |address/none
4|disassmebly|u|address/none|length
5|display registers|r|register/none
6|modify registers| r|register=value|
7|display memory|dd|address|length
8|modify memory|ed|address|value
9|set software bp|bp|address|length
10|list software bp|bl
11|delete software bp|bc|index
12|set memory bp| bm|address|type(a/w)|length
13|list memory bp|bml
14|delete memory bp|bmc|index
15|set hardware bp|ba|address|type <br> 0 = execute, 3 = access|length<br> 0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes
16|list hardware bp| bal
17|delete hardware bp|bac|index
18|execute till return| ret
19| list modules | lm
