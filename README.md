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
12|set memory bp| bm|type <br> a = access, w = write|length|address
13|list memory bp|bml
14|delete memory bp|bmc|index
15|set hardware bp|ba|address|type <br> 0 = execute, 3 = access|length<br> 0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes
16|list hardware bp| bal
17|delete hardware bp|bac|index
18|execute till return| ret
19| list modules | lm
## Usage
### 1. Launch Debugger
Launch the debugger by specifying the path to the target executable you want to debug.
-exec <target_path>
### 2. Debug Commands
Once the debugger is running, you can use various commands from the command-line interface to control and analyze the target program.
## Screenshots
![image](https://github.com/user-attachments/assets/971501af-2ba1-402a-b623-0caca93b15fc)
![image](https://github.com/user-attachments/assets/3dd4f06b-c145-4d2f-9667-d64cee633d92)
![image](https://github.com/user-attachments/assets/b39118e8-cb1e-4138-a157-fff6529eb1ba)









