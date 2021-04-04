# 预备知识
## 文件操作
### open
```c
int open(const char *path, int flags, [mode_t mode]);
//如果操作成功则返回一个文件描述符，否则返回-1；
```
- path：是要打开或创建文件的名字或路径，对于路径名来说必须是绝对路径，而文件名是相对路径（当前目录下）。

- flags：表示打开文件所采用的操作，需要注意的是：必须指定以下三个常量的一种，且只允许指定一个：

  - O_RDONLY：只读模式
  - O_WRONLY：只写模式
  - O_RDWR：可读可写

  以下的常量是选用的，这些选项是用来和上面的必选项进行按位或起来作为flags参数。

  - O_APPEND：表示追加，如果原来文件里面有内容，则这次写入会写在文件的最末尾。

  - O_CREAT：表示如果指定文件不存在，则创建这个文件

  - O_EXCL ：表示如果要创建的文件已存在，则出错，同时返回 -1，并且修改 errno 的值。

  - O_TRUNC：表示截断，如果文件存在，并且以只写、读写方式打开，则将其长度截断为0。

  - O_NOCTTY：如果路径名指向终端设备，不要把这个设备用作控制终端。

  - O_NONBLOCK：如果路径名指向 FIFO/块文件/字符文件，则把文件的打开和后继 I/O设置为非阻塞模式（nonblocking mode）

  以下三个常量同样是选用的，它们用于同步输入输出

  - O_DSYNC：等待物理 I/O 结束后再 write。在不影响读取新写入的数据的前提下，不等待文件属性更新。
  - O_RSYNC：read 等待所有写入同一区域的写操作完成后再进行
  - O_SYNC：等待物理 I/O 结束后再 write，包括更新文件属性的 I/O

### close

```c
int close(int fd);
//返回值：若成功，返回0；若出错，返回-1；
```

关闭一个文件时还会释放该进程加在该文件上的锁。当一个进程终止时，内核自动关闭它所有的打开文件。

###  lseek

```c
off_t lseek(int fd, off_t offset, int whence);
//返回值：若成功，返回新的文件偏移量；若出错，返回-1；
```

对于参数`offset`的解释与参数`whence`的值有关。

- 若`whence`是`SEEK_SET`，则将该文件的偏移量设置为距文件开始处`offset`个字节。
- 若`whence`是`SEEK_CURT`，则将该文件的偏移量设置为其当前值加`offset`，`offset`可正可负。
- 若`whence`是`SEEK_END`，则将该文件的偏移量设置为文件长度加`offset`，`offset`可正可负。

我们可以通过以下方式确定打开文件的偏移量：

```c
off_t currpos;
currpos = lseek(fd, 0, SEEL_CUR);
```

这种方法也可以用来确定设计的文件是否可以设置偏移量，如果文件描述符指向的是一个管道、FIFO或网络套接字，则`lseek`返回-1，并将`errno`设置为`ESPIPE`。

### read

```c
ssize_t read(int fd, void *buf, size_t nbytes);
//返回值：读到的字节数，若已到文件尾，返回0；若出错，返回-1；
```

有多种情况可使实际读到的字节数少于要求的字节数：

- 读普通文件时，在读到要求字节数之前已到达了文件末尾。
- 当从终端设备读时，通常一次最多读一行。
- 当从网络读时，网络中的缓冲机制可能造成返回值小于所要求的字节数。
- 当从管道或FIFO读时，如若管道包含的字节少于所需的数量，则只返回实际读到的字节数。
- 当从某些面向记录的设备读时，一次最多返回一个记录。
- 当一信号造成中断，而已经读了部分数据量时。

### write

```c
ssize_t write(int fd, const void *buf, size_t nbytes);
//返回值：若成功，返回已写字节数；若出错，返回-1；
```

在一次写成功后，文件偏移数量增加实际写的字节数。

### dup/dup2

```c
int dup(int fd);
int dup2(int fd, int fd2);
//两函数的返回值：若成功，返回新的文件描述符；若出错，返回-1；
```

由`dup`返回的新文件描述符一定数当前可用文件描述符中的最小值。对于`dup2`，可以用`fd2`参数指定新描述符的值。如果`fd2`已经打开，则先将其关闭。若`fd`等于`fd2`，则`dup2`返回`fd2`，而不关闭它。

这些函数返回的新文件描述符与参数`fd`共享同一个文件表项。且两个函数都为原子操作。

### fcntl

```c
int fcntl(int fd, int cmd, [int arg]);
//返回值：若成功，则依赖于cmd；若出错，返回-1；
```

`fcntl`有以下5种功能：

- 复制一个已有的描述符（`cmd`=`F_DUPFD`或`cmd`=`F_DUPFD_CLOEXEC`）。

  不同点是，`F_DUPFD_CLOEXEC`会设置`CLOSE_ON_EXEC`，即当执行execve的时候，文件描述符将被关闭。

- 获取/设置文件描述符标志（`cmd`=`F_GETFD`或`cmd`=`F_SETFD`）。

- 获取/设置文件状态标志（`cmd`=`F_GETFL`或`cmd`=`F_SETFL`）。

- 获取/设置异步I/O所有权（`cmd`=`F_GETOWN`或`cmd`=`F_SETOWN`）。

- 获取/设置记录锁（`cmd`=`F_GETLK`、`F_SETLK`或`cmd`=`F_SETLKW`）。

### perror

```c
void perror(const char *msg);
```

`perror`基于`errno`的当前值，在标准错误上产生一条出错消息，然后返回。它首先输出由`msg`指向的字符串，然后是一个冒号，一个空格，接着是对应于`errno`值得出错消息，最后是一个换行符。

## 进程

### 程序进程的区别
进程（Process）是最初定义在Unix等多用户、多任务操作系统环境下用于表示应用程序在内存环境中基本执行单元的概念。以Unix操作系统为例，进程是Unix操作系统环境中的基本成分、是系统资源分配的基本单位。Unix操作系统中完成的几乎所有用户管理和资源分配等工作都是通过操作系统对应用程序进程的控制来实现的。       

C、C++、Java等语言编写的源程序经相应的编译器编译成可执行文件后，提交给计算机处理器运行。这时，处在可执行状态中的应用程序称为进程。从用户角度来看，进程是应用程序的一个执行过程。从操作系统核心角度来看，进程代表的是操作系统分配的内存、CPU时间片等资源的基本单位，是为正在运行的程序提供的运行环境。**进程与应用程序的区别**在于应用程序作为**一个静态文件存储在计算机系统的硬盘等存储空间中**，而进程则是**处于动态条件下由操作系统维护的系统资源管理实体**。      

多任务环境下应用程序进程的主要特点包括：       

- 进程在执行过程中有内存单元的初始入口点，并且进程存活过程中始终拥有独立的内存地址空间；       

- 进程的生存期状态包括创建、就绪、运行、阻塞和死亡等类型；       

- 从应用程序进程在执行过程中向CPU发出的运行指令形式不同，可以将进程的状态分为用户态和核心态。处于用户态下的进程执行的是应用程序指令、处于核心态下的应用程序进程执行的是操作系统指令。       

在Unix操作系统启动过程中，系统自动创建swapper、init等系统进程，用于管理内存资源以及对用户进程进行调度等。在Unix环境下无论是由操作系统创建的进程还要由应用程序执行创建的进程，均拥有唯一的进程标识（PID）

### 并行并发区别

![并行并发](G:\CTF\learn\picture\并行并发.jpg)

**并发**

当我们谈论至少两个或更多任务时，并发这个定义是适用的。当一个应用程序实际上可以同时执行两个任务时，我们将其称为并发应用程序。尽管这里的任务看起来像是同时运行的，但实际上它们可能不一样。它们利用操作系统的CPU时间分片功能，其中每个任务运行其任务的一部分，然后进入等待状态。当第一个任务处于等待状态时，会将CPU分配给第二个任务以完成其一部分任务。
操作系统根据任务的优先级分配CPU和其他计算资源，例如内存;依次处理所有任务，并给他们完成任务的机会。对于最终结果来看，用户感觉所有任务都是同时运行的，这称为并发。

**并行**

并行不需要两个任务存在。通过为每个任务或子任务分配一个内核，它实际上使用多核CPU基础结构同时运行部分任务或多个任务。
并行性本质上要求具有多个处理单元的硬件。在单核CPU中，您可能会获得并发性，但不能获得并行性。
并发与并行之间的区别现在，让我们列出并发与并行之间的显着区别。并发是两个任务可以在重叠的时间段内启动，运行和完成的时间。并行是指任务实际上在同一时间运行，例如。在多核处理器上。
并发是由独立执行的进程组成，而并行性是同时执行（相关的）计算。
并发就是一次处理很多事情。并行是关于一次做很多事情。
一个应用程序可以是并发的，但不能是并行的，这意味着它可以同时处理多个任务，但是没有两个任务可以同时执行。
一个应用程序可以是并行的，但不能是并发的，这意味着它可以同时处理多核CPU中一个任务的多个子任务。
一个应用程序既不能是并行的，也不能是并发的，这意味着它一次顺序地处理所有任务。
一个应用程序可以是并行的，也可以是并发的，这意味着它可以同时在多核CPU中同时处理多个任务。

## PCB

进程控制块(PCB)（系统为了管理进程设置的一个专门的数据结构，用它来记录进程的外部特征，描述进程的运动变化过程。系统利用PCB来控和管理进程，所以PCB是系统感知进程存在的唯一标志。进程与PCB是一一对应的）在不同的操作系统中对进程的控制和管理机制不同，PCB中的信息多少不一样，通常PCB应包含如下一些信息。

1、进程标识符name：每个进程都必须有一个唯一的标识符，可以是字符串，也可以是一个数字。

2、进程当前状态 status：说明进程当前所处的状态。为了管理的方便，系统设计时会将相同的状态的进程组成一个队列，如就绪进程队列，等待进程则要根据等待的事件组成多个等待队列，如等待打印机队列、等待磁盘I/O完成队列等等。

3、进程相应的程序和数据地址，以便把PCB与其程序和数据联系起来。

4、进程资源清单。列出所拥有的除CPU外的资源记录，如拥有的I/O设备，打开的文件列表等。

5、进程优先级 priority：进程的优先级反映进程的紧迫程度，通常由用户指定和系统设置。

6、CPU现场保护区 cpustatus：当进程因某种原因不能继续占用CPU时（如等待打印机），释放CPU，这时就要将CPU的各种状态信息保护起来，为将来再次得到处理机恢复CPU的各种状态，继续运行。

7、进程同步与通信机制 用于实现进程间互斥、同步和通信所需的信号量等。

8、进程所在队列PCB的链接字 根据进程所处的现行状态，进程相的PCB参加到不同队列中。PCB链接字指出该进程所在队列中下一个进程PCB的首地址。

9、与进程有关的其他信息。 如进程记账信息，进程占用CPU的时间等。

```c
struct task_struct
{
	volatile long state; //说明了该进程是否可以执行，还是可中断等信息
	unsigned long flags; // flags 是进程号，在调用fork()时给出
	int sigpending; // 进程上是否有待处理的信号
 
	 mm_segment_t addr_limit;  //进程地址空间,区分内核进程与普通进程在内存存放的位置不同  //0-0xBFFFFFFF for user-thead    //0-0xFFFFFFFF for kernel-thread
	 //调度标志,表示该进程是否需要重新调度,若非0,则当从内核态返回到用户态,会发生调度
	 volatile long need_resched;
	 int lock_depth;    //锁深度
	 long nice;       //进程的基本时间片
 
	 //进程的调度策略,有三种,实时进程:SCHED_FIFO,SCHED_RR, 分时进程:SCHED_OTHER
	 unsigned long policy;
	 struct mm_struct *mm;    //进程内存管理信息
 
	 int processor;
	 //若进程不在任何CPU上运行, cpus_runnable 的值是0，否则是1 这个值在运行队列被锁时更新
	 unsigned long cpus_runnable, cpus_allowed;
	 struct list_head run_list;   //指向运行队列的指针
	 unsigned long sleep_time;   //进程的睡眠时间
 
	 //用于将系统中所有的进程连成一个双向循环链表, 其根是init_task
	 struct task_struct *next_task, *prev_task;
	 struct mm_struct *active_mm;
	 struct list_head local_pages;      //指向本地页面      
	 unsigned int allocation_order, nr_local_pages;
	 struct linux_binfmt *binfmt;      //进程所运行的可执行文件的格式
	 int exit_code, exit_signal;
	 int pdeath_signal;           //父进程终止时向子进程发送的信号
	 unsigned long personality;
	 //Linux可以运行由其他UNIX操作系统生成的符合iBCS2标准的程序
	 int did_exec:1; 
	 pid_t pid;          //进程标识符,用来代表一个进程
	 pid_t pgrp;        //进程组标识,表示进程所属的进程组
	 pid_t tty_old_pgrp;      //进程控制终端所在的组标识
	 pid_t session;             //进程的会话标识
	 pid_t tgid;
	 int leader;    //表示进程是否为会话主管
	 struct task_struct *p_opptr,*p_pptr,*p_cptr,*p_ysptr,*p_osptr;
	 struct list_head thread_group;          //线程链表
	 struct task_struct *pidhash_next;    //用于将进程链入HASH表
	 struct task_struct **pidhash_pprev;
	 wait_queue_head_t wait_chldexit;      //供wait4()使用
	 struct completion *vfork_done;         //供vfork() 使用
 
 
	 unsigned long rt_priority;       //实时优先级，用它计算实时进程调度时的weight值
 
 
	 //it_real_value，it_real_incr用于REAL定时器，单位为jiffies, 系统根据it_real_value
 
	 //设置定时器的第一个终止时间. 在定时器到期时，向进程发送SIGALRM信号，同时根据
 
	 //it_real_incr重置终止时间，it_prof_value，it_prof_incr用于Profile定时器，单位为jiffies。
 
	 //当进程运行时，不管在何种状态下，每个tick都使it_prof_value值减一，当减到0时，向进程发送
 
	 //信号SIGPROF，并根据it_prof_incr重置时间.
	 //it_virt_value，it_virt_value用于Virtual定时器，单位为jiffies。当进程运行时，不管在何种
 
	 //状态下，每个tick都使it_virt_value值减一当减到0时，向进程发送信号SIGVTALRM，根据
 
	 //it_virt_incr重置初值。
 
	 unsigned long it_real_value, it_prof_value, it_virt_value;
	 unsigned long it_real_incr, it_prof_incr, it_virt_value;
	 struct timer_list real_timer;        //指向实时定时器的指针
	 struct tms times;                      //记录进程消耗的时间
	 unsigned long start_time;          //进程创建的时间
 
	 //记录进程在每个CPU上所消耗的用户态时间和核心态时间
	 long per_cpu_utime[NR_CPUS], per_cpu_stime[NR_CPUS]; 
 
 
	 //内存缺页和交换信息:
 
	 //min_flt, maj_flt累计进程的次缺页数（Copy on　Write页和匿名页）和主缺页数（从映射文件或交换
 
	 //设备读入的页面数）； nswap记录进程累计换出的页面数，即写到交换设备上的页面数。
	 //cmin_flt, cmaj_flt, cnswap记录本进程为祖先的所有子孙进程的累计次缺页数，主缺页数和换出页面数。
 
	 //在父进程回收终止的子进程时，父进程会将子进程的这些信息累计到自己结构的这些域中
	 unsigned long min_flt, maj_flt, nswap, cmin_flt, cmaj_flt, cnswap;
	 int swappable:1; //表示进程的虚拟地址空间是否允许换出
	 //进程认证信息
	 //uid,gid为运行该进程的用户的用户标识符和组标识符，通常是进程创建者的uid，gid
 
	 //euid，egid为有效uid,gid
	 //fsuid，fsgid为文件系统uid,gid，这两个ID号通常与有效uid,gid相等，在检查对于文件
 
	 //系统的访问权限时使用他们。
	 //suid，sgid为备份uid,gid
	 uid_t uid,euid,suid,fsuid;
	 gid_t gid,egid,sgid,fsgid;
	 int ngroups;                  //记录进程在多少个用户组中
	 gid_t groups[NGROUPS];      //记录进程所在的组
 
	 //进程的权能，分别是有效位集合，继承位集合，允许位集合
	 kernel_cap_t cap_effective, cap_inheritable, cap_permitted;
 
	 int keep_capabilities:1;
	 struct user_struct *user;
	 struct rlimit rlim[RLIM_NLIMITS];    //与进程相关的资源限制信息
	 unsigned short used_math;         //是否使用FPU
	 char comm[16];                      //进程正在运行的可执行文件名
	 int link_count, total_link_ count;  //文件系统信息
 
	 //NULL if no tty 进程所在的控制终端，如果不需要控制终端，则该指针为空
	 struct tty_struct *tty;
	 unsigned int locks;
	 //进程间通信信息
	 struct sem_undo *semundo;       //进程在信号灯上的所有undo操作
	 struct sem_queue *semsleeping;   //当进程因为信号灯操作而挂起时，他在该队列中记录等待的操作
	 //进程的CPU状态，切换时，要保存到停止进程的task_struct中
	 struct thread_struct thread;
	 struct fs_struct *fs;           //文件系统信息
	 struct files_struct *files;    //打开文件信息
	 spinlock_t sigmask_lock;   //信号处理函数
	 struct signal_struct *sig;   //信号处理函数
	 sigset_t blocked;                //进程当前要阻塞的信号，每个信号对应一位
	 struct sigpending pending;      //进程上是否有待处理的信号
	 unsigned long sas_ss_sp;
	 size_t sas_ss_size;
	 int (*notifier)(void *priv);
	 void *notifier_data;
	 sigset_t *notifier_mask;
	 u32 parent_exec_id;
	 u32 self_exec_id;
 
	 spinlock_t alloc_lock;
	 void *journal_info;
}
```

volatile long state 标识进程的状态，可为下列六种状态之一：

- 可运行状态(TASK-RUNING);
- 可中断阻塞状态(TASK-UBERRUPTIBLE)
- 不可中断阻塞状态(TASK-UNINTERRUPTIBLE)
- 僵死状态(TASK-ZOMBLE)
- 暂停态(TASK_STOPPED)
- 交换态(TASK_SWAPPING)

### 创建进程时内核的操作

0号进程被称为`swapper`进程，该进程是内核的一部分，她并不执行任何磁盘上的程序，因此也被称为系统进程。进程ID 1通常是`init`进程，在自举过程结束时由内核调用，负责在自举内核后启动一个UNIX系统。

进程ID 2是页守护进程（page daemon），此进程负责支持虚拟存储器系统的分页操作。

一个现有进程可以调用`fork`函数创建一个新进程，而0号进程之前并没有任何进程。而0号进程的数据和用户信息等全部都是强制设置的，没有可复制和参考的对象。**其他的进程都是从0号`fork`来的。

#### 引发0x80中断

```c
#define _syscall0(type,name) /   
type name(void) /  
{ /  
long __res; /  
__asm__ volatile ( "int $0x80" /    // 调用系统中断0x80。   
:"=a" (__res) /     				// 返回值??eax(__res)。   
:"0" (__NR_##name)); /           	// 输入为系统中断调用号__NR_name。   
      if (__res >= 0) /      		// 如果返回值>=0，则直接返回该值。   
      return (type) __res; errno = -__res; /    // 否则置出错号，并返回-1。   
      return -1;}
```

这样使用`int 0x80`中断，调用`sys_fork`系统调用来创建进程。

#### sys_fork

```assembly
_sys_fork:  
call _find_empty_process # 调用find_empty_process()(kernel/fork.c,135)。  
testl %eax,%eax  
js 1f  
push %gs  
pushl %esi  
pushl %edi  
pushl %ebp  
pushl %eax  
call _copy_process 		# 调用C 函数copy_process()(kernel/fork.c,68)。  
addl $20,%esp 			# 丢弃这里所有压栈内容。  
1: ret  
```

首先调用的是`find_empty_process()`，然后又调用了`copy_process()`，而这两个函数就是fork.c中的函数。下面我们来看一下这两个函数。

#### find_empty_process

```c
int  find_empty_process (void)  
{  
  int i;  

repeat:  
  if ((++last_pid) < 0)  
    last_pid = 1;  
  for (i = 0; i < NR_TASKS; i++)  
    if (task[i] && task[i]->pid == last_pid)  
      goto repeat;  
  for (i = 1; i < NR_TASKS; i++) // 任务0 排除在外。  
    if (!task[i])  
      return i;  
  return -EAGAIN;  
} 
```

`find_empty_process`的作用就是为所要创建的进程分配一个进程号。在内核中用全局变量`last_pid`来存放系统自开机以来累计的进程数，也将此变量用作新建进程的进程号。内核第一次遍历task[64]，如果&&条件成立说明`last_pid`已经被别的进程使用了，所以`++last_pid`，直到获取到新的进程号。第二次遍历task[64]，获得第一个空闲的i，也就是任务号。因为在linux0.11中，最多允许同时执行64个进程，所以如果当前的进程已满，就会返回`-EAGAIN`。

#### copy_process

获得进程号并且将一些寄存器的值压栈后，开始执行copy_process()，该函数主要负责以下的内容。

- 为子进程创建task_struct，将父进程的task_struct复制给子进程。
- 为子进程的task_struct,tss做个性化设置。
- 为子进程创建第一个页表，也将父进程的页表内容赋给这个页表。
- 子进程共享父进程的文件。
- 设置子进程的GDT项。
- 最后将子进程设置为就绪状态，使其可以参与进程间的轮转。

```c
int  copy_process (int nr, long ebp, long edi, long esi, long gs, long none,  
          long ebx, long ecx, long edx,  
          long fs, long es, long ds,  
          long eip, long cs, long eflags, long esp, long ss)  
{  
  struct task_struct *p;  
  int i;  
  struct file *f;  

  p = (struct task_struct *) get_free_page ();  // 为新任务数据结构分配内存。  
  if (!p)           // 如果内存分配出错，则返回出错码并退出。  
    return -EAGAIN;  
  task[nr] = p;         // 将新任务结构指针放入任务数组中。  
// 其中nr 为任务号，由前面find_empty_process()返回。  
  *p = *current;        /* NOTE! this doesn't copy the supervisor stack */  
/* 注意！这样做不会复制超级用户的堆栈 */ （只复制当前进程内容）。  
    p->state = TASK_UNINTERRUPTIBLE; // 将新进程的状态先置为不可中断等待状态。  
  p->pid = last_pid;     // 新进程号。由前面调用find_empty_process()得到。  
  p->father = current->pid;   // 设置父进程号。  
  p->counter = p->priority;  
  p->signal = 0;     // 信号位图置0。  
  p->alarm = 0;  
  p->leader = 0;     /* process leadership doesn't inherit */  
/* 进程的领导权是不能继承的 */  
  p->utime = p->stime = 0;    // 初始化用户态时间和核心态时间。  
  p->cutime = p->cstime = 0;  // 初始化子进程用户态和核心态时间。  
  p->start_time = jiffies;   // 当前滴答数时间。  
// 以下设置任务状态段TSS 所需的数据（参见列表后说明）。  
  p->tss.back_link = 0;  
  p->tss.esp0 = PAGE_SIZE + (long) p;    // 堆栈指针（由于是给任务结构p 分配了1 页  
// 新内存，所以此时esp0 正好指向该页顶端）。  
  p->tss.ss0 = 0x10;     // 堆栈段选择符（内核数据段）[??]。  
  p->tss.eip = eip;      // 指令代码指针。  
  p->tss.eflags = eflags;    // 标志寄存器。  
  p->tss.eax = 0;  
  p->tss.ecx = ecx;  
  p->tss.edx = edx;  
  p->tss.ebx = ebx;  
  p->tss.esp = esp;  
  p->tss.ebp = ebp;  
  p->tss.esi = esi;  
  p->tss.edi = edi;  
  p->tss.es = es & 0xffff;   // 段寄存器仅16 位有效。  
  p->tss.cs = cs & 0xffff;  
  p->tss.ss = ss & 0xffff;  
  p->tss.ds = ds & 0xffff;  
  p->tss.fs = fs & 0xffff;  
  p->tss.gs = gs & 0xffff;  
  p->tss.ldt = _LDT (nr);    // 该新任务nr 的局部描述符表选择符（LDT 的描述符在GDT 中）。  
  p->tss.trace_bitmap = 0x80000000;   
// 如果当前任务使用了协处理器，就保存其上下文。  
    if (last_task_used_math == current)  
    __asm__ ("clts ; fnsave %0"::"m" (p->tss.i387));  
// 设置新任务的代码和数据段基址、限长并复制页表。如果出错（返回值不是0），则复位任务数组中  
// 相应项并释放为该新任务分配的内存页。  
  if (copy_mem (nr, p))  
    {               // 返回不为0 表示出错。  
      task[nr] = NULL;  
      free_page ((long) p);  
      return -EAGAIN;  
    }  
// 如果父进程中有文件是打开的，则将对应文件的打开次数增1。  
  for (i = 0; i < NR_OPEN; i++)  
    if (f = p->filp[i])  
      f->f_count++;  
// 将当前进程（父进程）的pwd, root 和executable 引用次数均增1。  
  if (current->pwd)  
    current->pwd->i_count++;  
  if (current->root)  
    current->root->i_count++;  
  if (current->executable)  
    current->executable->i_count++;  
// 在GDT 中设置新任务的TSS 和LDT 描述符项，数据从task 结构中取。  
// 在任务切换时，任务寄存器tr 由CPU 自动加载。  
  set_tss_desc (gdt + (nr << 1) + FIRST_TSS_ENTRY, &(p->tss));  
  set_ldt_desc (gdt + (nr << 1) + FIRST_LDT_ENTRY, &(p->ldt));  
  p->state = TASK_RUNNING;   /* do this last, just in case */  
/* 最后再将新任务设置成可运行状态，以防万一 */  
  return last_pid;      // 返回新进程号（与任务号是不同的）。  
}
```

进入`copy_prossess`函数后，调用`get_free_page`函数，在主内存申请一个空闲页面，并将申请到的页面清0。将这个页面的指针强制类型转化成task_struct类型的指针，并挂接在task[nr]上，nr就是在`find_empty_process`中返回的任务号。

接下来的`*p=*current`将当前进程的指针赋给了子进程的，也就是说子进程继承了父进程一些重要的属性，当然这是不够的，所以接下来的一大堆代码都是为子进程做个性化设置的。

一般来讲，每个进程都要加载属于自己的代码、数据，所以`copy_process`设置子进程的内存地址。通过`copy_mem`来设置新任务的代码和数据段基址、限长并复制页表。

```c
int copy_mem (int nr, struct task_struct *p)  
{  
  unsigned long old_data_base, new_data_base, data_limit;  
  unsigned long old_code_base, new_code_base, code_limit;  

  code_limit = get_limit (0x0f);    // 取局部描述符表中代码段描述符项中段限长。  
  data_limit = get_limit (0x17);    // 取局部描述符表中数据段描述符项中段限长。  
  old_code_base = get_base (current->ldt[1]);    // 取原代码段基址。  
  old_data_base = get_base (current->ldt[2]);    // 取原数据段基址。  
  if (old_data_base != old_code_base)   // 0.11 版不支持代码和数据段分立的情况。  
    panic ("We don't support separate I&D");  
  if (data_limit < code_limit)   // 如果数据段长度 < 代码段长度也不对。  
    panic ("Bad data_limit");  
  new_data_base = new_code_base = nr * 0x4000000;   // 新基址=任务号*64Mb(任务大小)。  
  p->start_code = new_code_base;  
  set_base (p->ldt[1], new_code_base);   // 设置代码段描述符中基址域。  
  set_base (p->ldt[2], new_data_base);   // 设置数据段描述符中基址域。  
  if (copy_page_tables (old_data_base, new_data_base, data_limit))  
    {               // 复制代码和数据段。  
      free_page_tables (new_data_base, data_limit); // 如果出错则释放申请的内存。  
      return -ENOMEM;  
    }  
  return 0;  
}  
```

然后是对文件，pwd等资源的修改，接着要设置子进程在GDT中的表项，最后将进程设置为就绪状态，并返回进程号。

![](G:\CTF\learn\picture\进程创建.png)

### fork

`fork`函数执行一次（或者说调用一次），返回两次。在父进程中返回子进程的ID，在子进程中返回0。且子进程和父进程的执行顺序是不确定的。

### ps命令

**命令格式：**

ps[参数]

**命令功能：**

用来显示当前进程的状态

**命令参数：**

a 显示所有进程

-a 显示同一终端下的所有程序

-A 显示所有进程

c 显示进程的真实名称

-N 反向选择

-e 等于“-A”

e 显示环境变量

f 显示程序间的关系

-H 显示树状结构

r 显示当前终端的进程

T 显示当前终端的所有程序

u 指定用户的所有进程

-au 显示较详细的资讯

-aux 显示所有包含其他使用者的行程 

-C<命令> 列出指定命令的状况

--lines<行数> 每页显示的行数

--width<字符数> 每页显示的字符数

--help 显示帮助信息

--version 显示版本显示

### kill

```c
int kill(pid_t pid, int sig);
//返回值：成功则为0，若出错则为-1；
```

- 如果`pid`大于零，那么`kill`函数发送信号号码`sig`给进程`pid`。
- 如果`pid`等于零，那么`kill`发送信号`sig`给调用进程所在进程组中的每个进程，包括调用进程自己。
- 如果`pid`小于零，`kill`发送信号`sig`给进程组`|pid`（pid的绝对值）中的每个进程。

### getpid/getppid

```c
pid_t getpid(void);
pid_t getppid(void);
//返回值：调用者或其父进程的PID
```



思考题:

1. 如何循环生成n个子进程,并且这些子进程均为兄弟关系？

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/types.h>
    #include <unistd.h>

    int main()
    {
        int i = 0;
        for(i=0; i<3; i++)
        {
            //创建子进程
            pid_t pid = fork();
            if(pid<0) //fork失败的情况
            {
                perror("fork error");
                return -1;
            }
            else if(pid>0)	//父进程
            {
                printf("father: pid==[%d], fpid==[%d]\n", getpid(),getppid());
                //sleep(1);
            }
            else if(pid==0) //子进程
            {
                printf("child: pid==[%d], fpid==[%d]\n", getpid(), getppid());
                break;
            }
        }
        return 0;
    }
    ```
    
    若想让创建的子进程均为兄弟关系，则只能让父进程调用`fork`。而父进程和子进程的区别就在`fork`返回的PID，所以当PID=0时，要跳出循环，不让子进程再`fork`。
    
2. 父子进程能否共享全局变量?

   明显不能

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <sys/types.h>
   #include <unistd.h>
   
   int g_var=2;
   
   int main()
   {
       pid_t pid = fork();
       printf("Before: g_var %d\n",g_var);
       if(pid<0)
       {
           perror("fork error");
           return -1;
       }
       else if(pid>0)//父进程中
       {
           g_var--;
           //printf("g_var: %d in father: pid==[%d], fpid==[%d]\n", g_var, getpid(), getppid());
       }
       else if(pid==0)
       {
           g_var++;
           //printf("g_var: %d in child: pid==[%d], fpid==[%d]\n", g_var, getpid(), getppid());
       }
       printf("After: g_var %d\n",g_var);
   	return 0;
   }
   ```

   Output:

   ```c
   g_var: 1 in father: pid==[33952], fpid==[33930]
   g_var: 3 in child: pid==[33953], fpid==[33952]
       
   Before: g_var 2
   Before: g_var 2
   After: g_var 1
   After: g_var 3
   ```

   

3. 父子进程是否共享文件描述符,是否共享文件偏移量

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <sys/types.h>
   #include <unistd.h>
   
   int main()
   {
       char buf[100];
       pid_t pid = fork();
       int fp;
       off_t currpos;
   
   
       fp = open("flag.txt",O_RDWR);
       if(pid<0)
       {
           perror("fork error");
           return -1;
       }
       else if(pid>0)//父进程中
       {
           read(fp, buf, 5);
           currpos = lseek(fp, 0, SEEK_CUR);
           printf("buf: %s currpos: %d in father: pid==[%d], fpid==[%d]\n",buf, currpos, getpid(), getppid());
   
       }
       else if(pid==0)
       {
           read(fp, buf, 10);
           currpos = lseek(fp, 0, SEEK_CUR);
           printf("buf :%s currpos: %d in child: pid==[%d], fpid==[%d]\n",buf, currpos, getpid(), getppid());
       }
       
   	return 0;
   }
   ```

   Output:

   ```c
   buf: ABCDE currpos: 5 in father: pid==[34662], fpid==[33930]
   buf :ABCDEFGHIJ currpos: 10 in child: pid==[34663], fpid==[34662]
   ```

### wait/waitpid

```c
pid_t waitpid(pid_t pid, int *statusp, int options);
//返回值：如果成功，则为子进程的PID，如果WHOHANG，则为0，如果其他错误，则为-1；
```

等待集合的成员是由参数`pid`来确定的：

- `pid`>0，那么等待集合就算一个单独的子进程，它的进程ID等于`pid`。
- `pid`=-1，那么等待集合就算父进程所有的子进程。

可以通过将``options`设置为常量`WHOHANG`、`WUNTRACED`和`WCONTINUED`的各种组合来修改默认行为：

- `WHOHANG`：如果等待集合中的任何子进程都还没有终止，那么立即返回（返回值为0）。默认的行为是挂起调用进程，直到有子进程终止。
- `WUNTRACED`：挂起调用进程的执行，直到等待集合中的一个进程变成已终止或者被停止。返回的PID为导致返回的已终止或被停止子进程的PID。默认的行为是只返回已终止的子进程。
- `WCONTINUED`：挂起调用进程的执行，直到等待集合中一个正在运行的进程终止或等待集合中一个被停止的进程收到`SIGCONT`信号重新开始执行
- 以上选项可以用或运算组合起来

```c
pid_t wait(int *statusp);
//返回值：如果成功，则为子进程PID，若出错，则为-1；
```

### exec函数族

```c
#include <unistd.h>

int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg,..., char * const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[],char *const envp[]);
//返回值：若成功，不返回，若出错，返回-1；
```

exec族函数参数极难记忆和分辨，函数名中的字符会给我们一些帮助：

- l : 使用参数列表
- p：使用文件名，并从PATH环境进行寻找可执行文件
- v：应先构造一个指向各参数的指针数组，然后将该数组的地址作为这些函数的参数。
- e：多了envp[]数组，使用新的环境变量代替调用进程的环境变量

## 进程通信

### 管道

```c
#include <unistd.h>

int pipe(int pipefd[2]);
//返回值：成功返回0，失败返回-1；
```

管道又名匿名管道，这是一种最基本的IPC机制，由pipe函数创建。调用pipe函数时在内核中开辟一块缓冲区用于通信,它有一个读端，一个写端：fd[0]指向管道的读端，fd[1]指向管道的写端。所以管道在用户程序看起来就像一个打开的文件,通过read(fd[0])或者writefd[1])向这个文件读写数据，其实是在读写内核缓冲区。

管道出现的四种特殊情况：

- 写端关闭，读端不关闭；

  那么管道中剩余的数据都被读取后,再次read会返回0,就像读到文件末尾一样。

- 写端不关闭，但是也不写数据，读端不关闭；

  此时管道中剩余的数据都被读取之后再次read会被阻塞，直到管道中有数据可读了才重新读取数据并返回；

- 读端关闭，写端不关闭；

  此时该进程会收到信号SIGPIPE，通常会导致进程异常终止。

- 读端不关闭，但是也不读取数据，写端不关闭；

  此时当写端被写满之后再次write会阻塞，直到管道中有空位置了才会写入数据并重新返回。

管道是一种半双工的通信方式（现代已实现全双工），数据只能单向流动，而且只能在具有亲缘关系的进程间使用。进程的亲缘关系通常是指父子进程关系。

### FIFO

FIFO被成为命名管道，实现无亲缘关系进程间的数据交换。值的注意的是，命名管道严格遵循**先进先出(first in first out)**，对匿名管道及命名管道的读总是从开始处返回数据，对它们的写则把数据添加到末尾。它们不支持诸如lseek()等文件定位操作。**命名管道的路径名存在于文件系统中，内容存放在内存中。**

```c
#include<sys/stat.h>

int mkfifo(const char *path, mode_t mode);
int mkfifoai(int fd, const char *path, mode_t mode);
//返回值：都是成功返回0，失败返回-1；
```

FIFO是一种文件类型，在创建命名管道后，必须要使用`open`进行打开。

### 信号量

信号量的本质是一种数据操作锁，用来负责数据操作过程中的互斥，同步等功能。

信号量用来管理临界资源的。它本身只是一种外部资源的标识，不具有数据交换功能，而是通过控制其他的通信资源实现进程间通信。 可以这样理解，信号量就相当于是一个计数器，用于为多个进程提供对共享数据对象的访问。

为了获取共享资源，进程需要执行下列操作。

1. 测试控制该资源的信号量
2. 若此信号量的值为正，则进程可以使用该资源。在这种情况下，进程会将信号量减1，表示它使用了一个资源单位。
3. 否则，若此信号量的值为0，则进程进入休眠状态，直至信号量值大于0。进程被唤醒后，返回至步骤1。

当进程不再使用由一个信号量控制的共享资源时，该信号量值加1，如果有进程正在休眠等待此信号量，则唤醒它们。

内核为每个信号量集合维护着一个`semid_ds`结构：

```c
struct semid_ds {
    struct ipc_erm sem_perm;
    unsigned short sem_nsems;
    time_t sem_otime;		/*last-semop() time*/
    time_t sem_ctime;		/*last-change time*/
    ...
}
```

每个信号量由一个无名结构表示，它至少包含下了成员：

```c
struct {
    unsigned short semval;
    pid_t sempid;
    unsigned short semncnt;
    unsigned short semzcnt;
    ...
}
```

**信号量的创建**

```c
#include <sys/sem.h>
int semget(key_t key, int nsems, int semflg);
//返回值：成功返回信号量ID，失败返回-1。
```

nsems：这个参数表示你要创建的信号量集合中的信号量的个数。信号量只能以集合的形式创建。

**信号量的初始化**

```c
#include <sys/sem.h>
int semctl(int semid, int semnum, int cmd, [union semun arg]);
```

### 信号

当造成信号的事件发生时，为进程**产生**一个信号。

当对信号采取了这种动作时，我们说向进程**递送**了一个信号。

在信号产生和递送之间的时间间隔内，称信号是**未决**的。

```c
#include<signal.h>
typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
//返回值：若成功，返回以前的信号处理配置；若出错，返回SIG_ERR
```

通过`signal`修改和信号相关联的默认行为。唯一的例外是`STGSTOP`和`SIGKILL`它，们的默认行为是无法修改的。

- 如果handler是`SIG_IGN`，那么忽略类型为`signum`的信号。
- 如果handler是`SIG_DFL`，那么类型为`signum`的信号恢复为默认行为。
- 否则，handler就是用户定义的函数地址，这个函数被称为**信号处理程序**，只要进程接收到一个类型为`signum`的型号，就会调用这个程序。

```c
#include<stdlib.h>
void abort(void);
//无返回值
```

`abort`函数的功能是使程序异常终止，将`SIGABRT`信号发送给调用进程。

```c
int setitimer(int which, const struct itimerval *value, struct itimerval *ovalue));
```

`setitimer`为Linux的API，并非C语言的Standard Library，setitimer()有两个功能，一是指定一段时间后，才执行某个function，二是每间格一段时间就执行某个function。

其中，which为定时器类型，3种类型定时器如下：

- ITIMER_REAL : 以系统真实的时间来计算，它送出SIGALRM信号。　　
- ITIMER_VIRTUAL : -以该进程在用户态下花费的时间来计算，它送出SIGVTALRM信号。　　
- ITIMER_PROF : 以该进程在用户态下和内核态下所费的时间来计算，它送出SIGPROF信号。

第二个参数指定间隔时间，第三个参数用来返回上一次定时器的间隔时间，如果不关心该值可设为NULL。

`it_interval`指定间隔时间，`it_value`指定初始定时时间。如果只指定`it_value`，就是实现一次定时；如果同时指定 `it_interval`，则超时后，系统会重新初始化`it_value`为`it_interval`，实现重复定时；两者都清零，则会清除定时器。　　

`tv_sec`提供秒级精度，`tv_usec`提供微秒级精度，以值大的为先，注意1s = 1000000us。　

如果是以setitimer提供的定时器来休眠，只需阻塞等待定时器信号就可以了。

一秒计算数的数字：

```c
#include <stdio.h>       
#include <unistd.h>       
#include <signal.h>        
#include <string.h>        
#include <sys/time.h>    

static int count = 0;

void printMes(int signo)
{
    printf("Get a SIGALRM, %d counts!\n", count);
    exit(0);
}

int main()
{
    int res = 0;
    struct itimerval tick;
    
    signal(SIGALRM, printMes);
    memset(&tick, 0, sizeof(tick));

    //Timeout to run first time
    tick.it_value.tv_sec = 1;
    tick.it_value.tv_usec = 0;

    //After first, the Interval time for clock
    tick.it_interval.tv_sec = 0;
    tick.it_interval.tv_usec = 0;

    if(setitimer(ITIMER_REAL, &tick, NULL) < 0)
            printf("Set timer failed!\n");

    for(count=0;;count++);
    return 0;
}
```

该示例程序每隔1s产生一行标准输出:

```c
#include <stdio.h>       
#include <unistd.h>       
#include <signal.h>        
#include <string.h>        
#include <sys/time.h>    

static int count = 0;

void printMes(int signo)
{
    printf("Get a SIGALRM, %d counts!\n", ++count);
}

int main()
{
    int res = 0;
    struct itimerval tick;
    
    signal(SIGALRM, printMes);
    memset(&tick, 0, sizeof(tick));

    //Timeout to run first time
    tick.it_value.tv_sec = 1;
    tick.it_value.tv_usec = 0;

    //After first, the Interval time for clock
    tick.it_interval.tv_sec = 1;
    tick.it_interval.tv_usec = 0;

    if(setitimer(ITIMER_REAL, &tick, NULL) < 0)
            printf("Set timer failed!\n");

    //When get a SIGALRM, the main process will enter another loop for pause()
    while(1)
    {
        pause();
    }
    return 0;
}
```

#### 信号集

```c
#include<signal.h>
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signo);
int sigdelset(sigset_t *set, int signo);
//返回值：若成功，返回0；若出错，返回-1

int sigismember(const sigset_t *set, int signo);
//返回值：若真，返回1，若假，返回0
```

`sigemptyset`初始化由`set`指向的信号集，消除其中的所有信号。`sigfillset`初始化由`set`指向的信号集，使其包括所有信号。

`sigaddset`向信号集中添加一个信号，`sigdelset`从信号集中删除一个信号。

```c
int sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict oset);
//返回值：若成功，返回0；若出错，返回-1。
```

首先，**若oset是非空指针，那么进程的当前信号屏蔽字通过oset返回。**

其次，**若set是一个非空指针，则参数how指示如何修改当前信号屏蔽字。**

|     how     |                             说明                             |
| :---------: | :----------------------------------------------------------: |
|  SIG_BLOCK  | 该进程新的信号屏蔽字是其当前信号屏蔽字和set指向信号集的并集。set包含了我们希望阻塞的附加信号 |
| SIG_UNBLOCK | 该进程新的信号屏蔽字是其当前信号屏蔽字和set所指向信号集补集的交集。set包含了我希望解除阻塞的信号 |
| SIG_SETMASK |       该进程新的信号屏蔽字将被set指向的信号集的值代替        |

如果set是空指针，则不改变该进程的信号屏蔽字，how的值也无意义。

在调用`sigprocmask`后如果有任何未决的、不再阻塞的信号，则在`sigprocmask`返回前，至少会将其中一个信号递送给该进程。

```c
int sigpending(sigset_t *set);
//返回值：若成功，返回0；若出错，返回-1
```

`sigpending`返回一信号集，对于调用进程而言，其中的各信号是阻塞不能递送的，因而也一定是当前未决的。

设置阻塞信号集并把所有常规信号的未决状态打印至屏幕:

```c
#include <stdio.h>       
#include <unistd.h>       
#include <signal.h>        
#include <string.h>        
#include <sys/time.h>    

void printit(sigset_t *set)
{
    int i = 0;
    for ( i = 0; i < 32; i++)
    {
        if(sigismember(set, i)==1)
            printf("1");
        else
            printf("0");     
    }
    printf("\n");
}

int main()
{
    sigset_t set, oldset, pendset;
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    sigprocmask(SIG_BLOCK, &set, &oldset);//阻塞SIGQUIT信号
    while (1)
    {
        sigpending(&pendset);
        printit(&pendset);
        sleep(1);
    } 

    return 0;
}
```
#### 信号捕捉函数
```c
int sigaction(int signo, const struct sigaction *restrict act, 
              struct sigaction *restrict oact);
//返回值：若成功，返回0；若出错，返回-1；
```

该函数取代了早期的`signal`函数。

其中，参数`signo`是要检测或修改其具体动作的信号编号。若`act`指针非空，则要修改其动作。如果`oact`指针非空，则系统经由`oact`指针返回该信号的上一个动作。

```c
struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_sigaction)(int, siginfo_t *, void *);
};
```

```c
#include <stdio.h>       
#include <unistd.h>       
#include <signal.h>        
#include <string.h>        
#include <sys/time.h>    

static int count = 0;

static void alrm_handler()
{
    printf("Get a SIGALRM %d count\n",count++);
    sleep(1);
}

int main()
{
    sigset_t set, oldset, pendset;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);

    pid_t pid;
    pid= getpid();

    signal(SIGALRM, alrm_handler);
    printf("pid : %d\n",pid);

    sigprocmask(SIG_BLOCK, &set, &oldset);
    sleep(5);
    for (int i = 0; i < 5; i++)
    {
        raise(SIGALRM);
    }
    
    sigdelset(&set, SIGALRM);
    sigprocmask(SIG_SETMASK, &set, &oldset);

    return 0;
}
```

在阻塞信号后，向自身发送五个信号，最终程序仅响应一个

#### sigchld函数

- 产生sigchld函数的条件
  - 子进程结束
  - 子进程收到sigstop
  - 子进程停止时收到了sigcont信号

## 线程

#### 进程与线程的区别与联系

[解释地很好的blog](http://www.ruanyifeng.com/blog/2013/04/processes_and_threads.html)

**之间的关系**

1. 一个线程只能属于一个进程，而一个进程可以有多个线程，但至少有一个线程（通常说的主线程）。
2. 资源分配给进程，同一进程的所有线程共享该进程的所有资源。
3. 线程在执行过程中，需要协作同步。不同进程的线程间要利用消息通信的办法实现同步。
4. 处理机分给线程，即真正在处理机上运行的是线程。
5. 线程是指进程内的一个执行单元，也是进程内的可调度实体。

**从三个角度来剖析二者之间的区别**

1. 调度：线程作为调度和分配的基本单位，进程作为拥有资源的基本单位。
2. 并发性：不仅进程之间可以并发执行，同一个进程的多个线程之间也可以并发执行。
3. 拥有资源：进程是拥有资源的一个独立单位，线程不拥有系统资源，但可以访问隶属于进程的资源。

用户进程主要段segment：stack，heap，.rodata，data/bss,.text。一个进程，上面的6部分是主要的，必须的。

线程只拥有stack（线程栈，线程栈是单个线程所独享的），保存自己的**函数调用过程**，比如heap，.rodata，data/bss，text段都是共享的。

#### 线程的底层原理

> 一切皆文件

从 Linux 内核的角度来看，并没有把线程和进程区别对待。

我们知道系统调用 fork() 可以新建一个子进程，函数 pthread() 可以新建一个线程。 但无论线程还是进程，都是用 task_struct 结构表示的，唯一的区别就是共享的数据区域不同 。

换句话说，线程看起来跟进程没有区别，只是线程的某些数据区域和其父进程是共享的，而子进程是拷贝副本，而不是共享。就比如说， mm 结构和 files 结构在线程中都是共享的。

线程ID是用`pthread_t`数据类型实现的，它可以用结构体来代表。所以需要有一个函数来进行线程ID的比较

```c
int pthread_equal(pthread_t tid1, pthread_t tid2);
//返回值：若相等，返回非零数值；否则，返回0；
```

使用`pthread_self`获取自身的线程ID。

```c
pthread_t pthread_self(void);
```

### 线程创建

```c
int pthread_create(pthread_t *restrict tidp,
                  const pthread_attr_t *restrict attr,
                  void *(*start_rtm)(void *), void *restrict arg);
//返回值：若成功，返回0；否则，返回错误编号
```

当`pthread_create`成功返回时，新创建线程的线程ID会被设置成`tidp`指向的内存单元。`attr`参数用于定制不同的线程属性。

新创建的线程从`start_rtn`函数的地址开始运行，该函数只有一个无类型指针参数`arg`。如果需要向`start_rtn`传递的参数有一个以上，那么需要把这些参数放到一个结构中，然后把这个结构的地址作为`arg`参数传入。

线程创建时并不能保证哪个线程会先运行。新创建的线程可以访问进程的地址空间，并且继承调用线程的浮点环境和信号屏蔽字，但是该线程的挂起信号集会被清除。

`pthread`函数在调用失败时通常会返回错误码，但并不会设置`errno`。

### 线程终止

单个进程可以通过三种方式退出，因此可以在不终止整个进程的情况下，停止它的控制流：

- 从启动例程中返回，返回值是线程的退出码；
- 被同一进程中的其他线程取消；
- 调用`pthread_exit`

```c
#include<pthread.h>
void pthread_exit(void *rval_ptr);
```

`rval_ptr`参数是一个无类型指针，与传给启动例程的单个参数类似。进程中的其他线程可以通过调用`pthread_join`函数访问到这个指针。

```c
int pthread_join(pthread_t thread, void **rval_ptr);
//返回值：若成功，返回0；否则，返回错误编号
```

调用线程将一直阻塞，直到指定的线程调用`pthread_exit`、从启动例程中返回或者被取消。如果线程简单地从它的启动例程返回，`rval_ptr`就包含返回码。如果线程被取消，由`rval_ptr`指定的内存单元就设置为`PTHREAD_CANCELED`。

### 线程取消

```c
int pthread_cancel(pthread_t tid);
//返回值：若成功，返回0；否则，返回错误编号
```

在默认情况下，`pthread_cancel`函数会使得由`tid`标识得线程得行为表现为如同调用了参数`PTHREAD_CANCELED`的`pthread_exit`函数，但是线程可以选择忽略取消或控制如何被取消。

### 线程同步

当有一个线程在对内存进行操作时，其他线程都不可以对这个内存地址进行操作，直到该线程完成操作， 其他线程才能对该内存地址进行操作，而其他线程又处于等待状态。

线程同步是为了确保线程安全，所谓线程安全指的是多个线程对同一资源进行访问时，有可能产生数据不一致问题，导致线程访问的资源并不是安全的。

#### 互斥量

可以使用`pthread`互斥接口来保护数据，互斥变量是用`pthread_mutex_t`数据类型表示的。在使用互斥变量以前，必须首先对它初始化，可以把它设置为常量`PTHREAD_MUTEX_INITIALIZER`，也可以通过调用`pthread_mutex_init`函数进行初始化，如果动态分配互斥量，在释放内存前需要调用`pthread_mutex_destroy`。

```c
int pthread_mutex_init(pthread_mutex_t *restrict mutex,
                      const pthread_mutexattr_t *restrict attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
//返回值：若成功，返回；否则，返回错误编号
```

要用默认的属性初始化互斥量，只需把`attr`设为NULL。

对互斥量进行加锁，需要调用`pthread_mutex_lock`。如果互斥量已经上锁，调用线程将阻塞直到互斥量被解锁。对互斥量解锁，需要调用`pthread_mutex_unlock`。

```c
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
//返回值：若成功，返回0；否则返回错误编号
```

如果不希望线程被阻塞，它可以使用`pthread_mutex_trylock`尝试i对互斥量进行加锁。如果调用`pthread_mutex_trylock`时互斥量处于未锁住状态，那么`pthread_mutex_trylock`将锁住互斥量，不会出现阻塞直接返回0，否则`pthread_mutex_trylock`就会失败，不能锁住互斥量，返回`EBUSY`。