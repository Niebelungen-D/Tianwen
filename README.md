# Tianwen
Homework of Tianwen

## week 1

1-4章笔记整理，Datalab+Bomblab+Attacklab

https://github.com/Niebelungen-D/Tianwen/tree/main/Week-1

## week 2

本周看完了书的第五章和第六章，做了archlab和cachelab，在arch part C上下了点功夫，iaddq+九路展开+三叉树查找+指令小优化，最后拿了56.6/60，自我感觉还不错，之后打算再看看能不能拿个满分。cachelab复习了一下线代知识（狗头

笔记链接：https://github.com/Niebelungen-D/Tianwen/tree/main/Week-2

shell lab在看，不过没什么思路还要再好好看看书。

做了几道pwnable.tw的题目：

https://niebelungen-d.top/tags/pwnable-tw/

## week 3

shell lab 

malloc lab：使用了书上的模板完成了框架，虽然加了fd，bk，但是搜索还是使用的隐式链表，需要调试，时间不太够就直接去搞proxy lab了（要重写

proxy lab：完成part A，B，还在调试Part c的bug。A，B在ppt上都给了解释与思路，C似乎在存储data（或者搜索？）的时候遇到了问题，只有第一个文件成功了，part B的测试也通过了。

**思考题：程序是怎样加载到内存运行的？**

父进程fork一个子进程，子进程通过 execve 系统调用启动加载器。

加载器删除子进程现有的虚拟内存段，并创建一组新的代码、数据、堆和栈段。新的栈和堆段被初始化为零。使用 mmap 将代码段和数据段映射到内存中。通过将虚拟地址空间中的页映射到可执行文件的页大小的片（chunk），新的代码段和数据段被初始化为可执行文件的内容。

加载程序依赖的链接库，并对其中的符号进行重定位。

最后，加载器跳转到_start 地址，它最终会调用应用程序的 main 函数。

