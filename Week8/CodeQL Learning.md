#  CodeQL Learning
关于环境的搭建可以参考[官方文档](https://codeql.github.com/docs/codeql-overview/)和[文章](https://paper.seebug.org/1078/)
## 基本

CodeQL的语句表示的是数据的关系，而不是处理。这与之前学习的编程语言有很大的不同。
看这个例子
```q
import cpp

from Function f
where f.getName() = "strlen"
select f
```
其中`Function`代表了所定义的所有函数，这是一个集合，第一句则可以理解从这个集合中进行查询。
`where`语句则指定了筛选条件，其中的元素只要满足这个条件才能`select`
而CodeQL中有很多集合，如`FunctionCall`、`Macro`和`MacroInvacation`等，我们可以定义两个来自不同集合的元素变量，在`where`中指定它们的关系。
```q
import cpp  
  
from FunctionCall call, Function f  
where call.getTarget() = f and f.getName() = "memcpy"  
select call
```
在这里我们定义了两个变量，一个的函数调用集合`FunctionCall`，另一个是函数集合`Function`，在`where`中我们要求，call调用了函数集合中的函数f，且函数名为`memcpy`，最终筛选出所有`memcpy`调用。
## 进阶
### 谓词
谓词是用来描述构成QL程序的逻辑关系的。
```q
predicate name(type arg1, type arg2)
{
  statements
}
```
定义谓词需要指定：
- 关键词`predicate`（无返回值），或者有返回值的类型
- 谓词名称，以小写字母开头的标识符
- 谓词参数
- 主体，这是用大括号括起来的逻辑公式

#### 无返回值的谓词
这类谓词的关键字为`predicate`，如果值满足主体中的逻辑属性，则谓词将保留该值。如：
```ql
import cpp

predicate isSmall(int i)
{
	i in [1...9]
}

from int i
where isSmall(i)
select i
```
从整数数据集合中，筛选出范围在1-9的元素。
#### 带返回值的谓词
在CodeQL中返回值是`result`，`result`变量可以像一般变量一样正常使用，唯一不同的是这个变量内的数据将会被返回。同时，**谓词可能返回多个结果，或者根本不返回任何结果**。
```ql
string getANeighbor(string country) {
  country = "France" and result = "Belgium"
  or
  country = "France" and result = "Germany"
  or
  country = "Germany" and result = "Austria"
  or
  country = "Germany" and result = "Belgium"
}
```
在这种情况下：
-   谓词调用`getANeighbor("Germany")`返回两个结果：`"Austria"`和 `"Belgium"`。
-   谓词调用不`getANeighbor("Belgium")`返回任何结果，因为`getANeighbor` 未定义`result`for `"Belgium"`

### 类
在CodeQL中，类代表了一类数据的集合，而不是一个对象。
要定义一个类，需要以下：
1.  关键字`class`。
2.  类的名称。这是一个 以大写字母开头的标识符。
3.  要扩展的类型。
4.  类的主体，用大括号括起来。

看这个例子
```q
class OneTwoThree extends int {  
	OneTwoThree() { 	// characteristic predicate  
 		this = 1 or this = 2 or this = 3  
	}  
   
	string getAString() { // member predicate  
 		result = "One, two or three: " + this.toString()  
 	}  
  
 	predicate isEven() { // member predicate  
 		this in [1 .. 2]    
 	}  
}  
  
from OneTwoThree i   
where i = 1 or i.getAString() = "One, two or three: 2"  
select i
```
这个类拓展到`int`类型，特征谓词`OneTwoThree()`限制了类所表示的数据集合。`this`表示当前类中包含的数据集合。
成员谓词
这些谓词仅适用于特定类别的成员。您可以根据值调用成员谓词。例如：
```q
1.(OneTwoThree).getAString()
```
最终返回：“One, two or three: 1”，这里1被转换成了`OneTwoThree`，这个转换会丢弃不属于该类集合的数据。
```q
exists(<variable declarations> | <formula>)
// 以下两个exists所表达的意思等价。
exists(<variable declarations> | <formula 1> | <formula 2>
exists(<variable declarations> | <formula 1> and <formula 2>
````
这个关键字的使用引入了一些新的变量。如果变量中至少有一组值可以使formula成立，那么该值将被保留。
看这个例子
```q
import cpp

class NetworkByteSwap extends Expr{
    NetworkByteSwap()
    {
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
          )
    }
}

from NetworkByteSwap n
select n, "Network byte swap"
```
这个类拓展到`Expr`类型，特征谓词`NetworkByteSwap()`限制了类所表示的数据集合。如果存在宏调用，其宏名称满足特定正则表达式，将这类数据保存至当前类的集合中。
#### 字段
在类中可以声明任意数量的字段，这些字段是限制在特征文字中的数据集合。可以理解为类集合的子集，也可以理解为继承。
```q
class SmallInt extends int {
  SmallInt() { this = [1 .. 10] }
}

class DivisibleInt extends SmallInt {
  SmallInt divisor;   // declaration of the field `divisor`
  DivisibleInt() { this % divisor = 0 }

  SmallInt getADivisor() { result = divisor }
}

from DivisibleInt i
select i, i.getADivisor()
```
-   每个类都不能继承自己
-   不能继承final类  
-   不能继承不相容的类

 **注意**：从某个基类派生出的类，将拥有基类的所有数据集合范围。如果某个类继承了多个基类，那么**该类内含的数据集合，将是两个基类数据集合的交集**。
#### 覆盖成员谓词
如果类从超类型继承成员谓词，则可以**覆盖**继承的定义。如果要优化谓词以为子类中的值提供更特定的结果，则此功能很有用。
```q
class OneTwo extends OneTwoThree {
  OneTwo() {
    this = 1 or this = 2
  }

  override string getAString() {
    result = "One or two: " + this.toString()
  }
}

from OneTwoThree o
select o, o.getAString()
```

| o    | `getAString()` result |
| :--- | :-------------------- |
| 1    | One or two: 1         |
| 2    | One or two: 2         |
| 2    | Two or three: 2       |
| 3    | Two or three: 3       |

## 数据流分析与污点追踪

### 局部数据流

局部数据流是在一个单独函数内的数据流追踪。局部数据流的库函数主要位于`DataFlow`模块中。该模块定义了一个类`Class`，这个类用于表示数据可以流经的任何元素。而`Node`类分为两种，分别是表达式节点`ExprNode`与参数节点`ParameterNode`。我们可以使用谓词`asExpr`与`asParameter`，将数据流结点与表达式节点/参数结点之间进行映射。参数结点`ParameterNode`指的是**当前函数参数**的数据流结点。

在函数内，查找从参数`source`到表达式`sink`的数据流

```q
DataFlow::localFlow(DataFlow::parameterNode(source), DataFlow::exprNode(sink))
```

### 局部污点追踪

```c++
int i = tainted_user_input();
some_big_struct *array = malloc(i * sizeof(some_big_struct));
```

由于输入的变量`i`被污染，因此使用变量`i`的`malloc`函数参数也被污染。

局部污点追踪的库函数主要位于`TaintTracking`模块中。与局部数据流分析类似，污点追踪同样有谓词`localTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo)`用于污点分析，同样有递归版本的`localTaint`谓词。

在函数内，查找从参数`source`到表达式`sink`的污点传播。

```q
TaintTracking::localTaint(DataFlow::parameterNode(source), DataFlow::exprNode(sink))
```

例子：

```q
import cpp
import semmle.code.cpp.dataflow.DataFlow

from Function fopen, FunctionCall fc, Expr src
where fopen.hasQualifiedName("fopen")
  and fc.getTarget() = fopen
  and DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(fc.getArgument(0)))
select src
```

该查询会输出可能流入`fopen`文件名参数的所有变量的表达式，主要展示API用法。

### 全局数据流

通过继承`DataFlow::Configuration`类来使用全局数据流库。

```q
class MyDataFlowConfiguration extends DataFlow::Configuration {
  MyDataFlowConfiguration() { this = "MyDataFlowConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    ...
  }

  override predicate isSink(DataFlow::Node sink) {
    ...
  }
}
```

在`DataFlow::Configuration`类中定义了如下几个谓词：

- `isSource`： **定义数据可能从何处流出**
- `isSink`： **定义数据可能流向的位置**
- `isBarrier`： 可选，限制数据流
- `isBarrierGuard`： 可选，限制数据流
- `isAdditionalFlowStep`： 可选，添加其他流程步骤

示例：

```q
from MyDataFlowConfiguration dataflow, DataFlow::Node source, DataFlow::Node sink
where dataflow.hasFlow(source, sink)
select source, "Data flow to $@.", sink, sink.toString()
```

### 全局污点追踪

通过继承`TaintTracking::Configuration`类以使用全局污点追踪的库函数。

```q
import semmle.code.cpp.dataflow.TaintTracking

class MyTaintTrackingConfiguration extends TaintTracking::Configuration {
  MyTaintTrackingConfiguration() { this = "MyTaintTrackingConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    ...
  }

  override predicate isSink(DataFlow::Node sink) {
    ...
  }
}
```

在配置中定义了以下谓词：

- `isSource`：定义污点可能从何处流出
- `isSink`：定义污点可能流入的地方
- `isSanitizer`：可选，限制污点流
- `isSanitizerGuard`：可选，限制污点流
- `isAdditionalTaintStep`：可选，添加其他污染步骤

使用谓词`hasFlow(DataFlow::Node source, DataFlow::Node sink)`以执行污点追踪分析。

```q
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
        )
        }
}
class Config extends TaintTracking::Configuration {		//全局数据流追踪类
    Config() { this = "NetworkToMemFuncLength" }
	// 覆写source，`instanceof`检查该值是否属于一个CodeQL类
    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }
	// 覆写sink
    override predicate isSink(DataFlow::Node sink) {
        exists( FunctionCall call |
            call.getTarget().getName() = "memcpy" and
            sink.asExpr() = call.getArgument(2) and
            not call.getArgument(1).isConstant()
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
```

## codeql-uboot

这是CodeQL的一个入门课程 [CodeQL U-Boot Challenge (C/C++)](https://lab.github.com/GitHubtraining/codeql-u-boot-challenge-(cc++))，我通过这个进行了基本的学习。
### Step 3
查询`strlen`函数
```q
import cpp

from Function f 				//从Function这个集合中查找
where f.getName() = "strlen"	//筛选其中名为`strlen`的函数
select f, "a function named strlen"
```
### Step 4
查询`memcpy`函数
```q
import cpp

from Function f 				//从Function这个集合中查找
where f.getName() = "memcpy"	//筛选其中名为`memcpy`的函数
select f, "a function named memcpy"
```
### Step 5
使用不同的类以及不同的谓语，查找名为`ntohs`、`ntohl`以及`ntohll`的宏定义。
```q
import cpp

from Macro m
where m.getName().regexpMatch("ntoh(s|l|ll)")	//正则匹配
select m
```
### Step 6
查找`memcpy`的调用
```q
import cpp  
  
from FunctionCall call, Function f  
where call.getTarget() = f and f.getName() = "memcpy"  
select call
```
### Step 7
查找宏定义的调用
```q
import cpp

from MacroInvocation mi
where mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)")
select mi
```
### Step 8
获取宏定义的表达式
```q
import cpp

from MacroInvocation mi
where mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)")
select mi.getExpr()
```
### Step 9
自定义类，查询宏定义表达式
```q
import cpp

class NetworkByteSwap extends Expr{
    NetworkByteSwap()
    {
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
          )
    }
}

from NetworkByteSwap n
select n, "Network byte swap"
```
### Step 10
使用全局数据流追踪，查询从`source`到`sink`在全局范围内的污点轨迹
```q
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
        )
        }
}
class Config extends TaintTracking::Configuration {		//全局数据流追踪类
    Config() { this = "NetworkToMemFuncLength" }
	// 覆写source，`instanceof`检查该值是否属于一个CodeQL类
    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }
	// 覆写sink
    override predicate isSink(DataFlow::Node sink) {
        exists( FunctionCall call |
            call.getTarget().getName() = "memcpy" and
            sink.asExpr() = call.getArgument(2) and
            not call.getArgument(1).isConstant()
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
```

在[这里](https://lgtm.com/)有很多项目进行实践

