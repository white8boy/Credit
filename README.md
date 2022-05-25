This is the code for the project "privacing credit evalution"

这是信用评估模型的代码实现，采用的是微软的SEAL库https://github.com/Microsoft/SEAL

具体实现代码在/native/examples中
以4_ckks_basics为开头的几个cpp文件即为具体实现代码，包含了优化版、初始版和服务器客户端分段版。

模型的输入和模型参数均为直接写在源代码中，而不是采用读取文件的方式。

根目录中的几个dat文件，分别用于写入和储存密文、参数、公钥和结果密文


在根目录执行 

cmake -S . -B build -DSEAL_BUILD_EXAMPLES=ON

cmake --build build

即可在build/bin 目录下获得二进制执行文件 
