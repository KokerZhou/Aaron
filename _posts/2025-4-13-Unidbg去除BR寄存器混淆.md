---
layout:     post
title:      unidbg模拟执行的去除ollvm混淆
subtitle:   deobfuscate to BR
date:       2025-4-13
author:     Aaron
header-img: img/vagabond.jpg
catalog: true
tags:
    - Rev
    - Android
    - deobf

---

## unidbg模拟执行的去除ollvm混淆

### 1.函数简单分析

对libtprt.so中的JNI_Onload函数进行去混淆

![](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250324222238242.png)

可以发现在函数后方使用了BR X9作为间接跳转，IDA无法分析控制流了，因为在此处X9为寄存器，在未执行时不知道寄存器的值为多少，所以静态看我们无法了解程序往哪走

![image-20250324222522858](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250324222522858.png)

F5反编译后可以看到jni->GetEnv函数后，执行BR X9后就无法看到其余逻辑了

![image-20250324222737563](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250324222737563.png)

在JNI_Onload下方还能看到许多对寄存器操作的汇编代码，猜测下方的汇编也为JNI_Onload执行的一部分

### 2.Unidbg环境的搭建

在这段混淆中我们使用模拟执行对函数进行去混淆

#### 2.1创建项目

直接在项目的unidbg-android/src/test/java目录下建立我们的模拟执行类：AntiOllvm

1. 创建64位模拟器实例,
   `emulator = AndroidEmulatorBuilder.for64Bit().build();`
2. 创建模拟器内存接口
   `Memory memory = emulator.getMemory();`
3. 设置系统类库解析
   `memory.setLibraryResolver(new AndroidResolver(23));`
4. 创建 Android 虚拟机
   `vm = emulator.createDalvikVM();`
5. 加载 so 到虚拟内存,第二个参数的意思表示是否执行动态库的初始化代码
   `DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/java/com/xxx/xxx.so"),true);`
6. 获取 so 模块的句柄
   `module = dm.getModule();`
7. 设置 JNI  需要继承`AbstractJni`
   `vm.setJni(this);`
8. 打印日志
   `vm.setVerbose(true);`
9. 调用 JNI_Onload
   `dm.callJNI_OnLoad(emulator);`
10. 创建 jobject， 如果没用到的话可以不写 ，要用需要调用函数所在的Java类完整路径，比如a/b/c/d等等，注意.需要用/代替
    `cNative = vm.resolveClass("com/xxx/xxx")`

加载动态库==>

```java
    public AntiOllvm() {
//        创建模拟器
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.antiollvm")
                .build();
        Memory memory = emulator.getMemory();
//        安卓SDK版本
        memory.setLibraryResolver(new AndroidResolver(23));
//        创建虚拟机
        vm = emulator.createDalvikVM();
        vm.setVerbose(true);

//        libtprt.so的依赖库
        vm.loadLibrary(new File("D:/unidbg/unidbg-android/src/main/resources/android/sdk23/lib64/libc.so"),false);
        vm.loadLibrary(new File("D:/unidbg/unidbg-android/src/main/resources/android/sdk23/lib64/libm.so"),false);
        vm.loadLibrary(new File("D:/unidbg/unidbg-android/src/main/resources/android/sdk23/lib64/libdl.so"),false);
        vm.loadLibrary(new File("D:/unidbg/unidbg-android/src/main/resources/android/sdk23/lib64/libstdcpp.so"),false);

        dm = vm.loadLibrary(new File("D:/unidbg/unidbg-android/src/test/resources/AntiOllvm/libtprt.so"), false);
        module = dm.getModule();
    }
```

加载后需要先执行jni_onload，而DalvikModule(dm)这个类已经实现了callJNI_OnLoad方法，我们直接调用即可

```java
    public void callJniOnload(){
        dm.callJNI_OnLoad(emulator);
    }
    public static void main(String[] args) {
        AntiOllvm AO = new AntiOllvm();
        AO.callJniOnload();
    }
```

![image-20250324224556059](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250324224556059.png)

可以看到在0x87670处进行了RegisterNative，注册的函数名为：initialize，地址在0x86e34

到这一步我们成功完成了使用Unidbg对安卓动态库的运行，并且正常运行了动态库的Jni_Onload函数

#### 2.2基本的指令hook

我们使用hook将每一步运行过的指令都打印出来

```java
public void logIns()
    {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user)  {
                Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64,Capstone.CS_MODE_ARM);
                byte[] bytes = emulator.getBackend().mem_read(address, 4);
                Instruction[] disasm = capstone.disasm(bytes, 0);
                System.out.printf("%x:%s %s\n",address-module.base ,disasm[0].getMnemonic(),disasm[0].getOpStr());
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base+start, module.base+end, null); 
    }
```

![image-20250325010000849](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250325010000849.png)

我们可以看到br x9往后执行的指令就是汇编代码中BR之后的指令

这段代码在unidbg中的作用是为指定模块的代码段添加**指令级动态跟踪钩子**，其效果是实时反汇编并打印该模块每条执行指令的详细信息。

---

**核心功能解析**

1. **钩子注册**

   ```java
   emulator.getBackend().hook_add_new(new CodeHook() { ... }, module.base, module.base+module.size, null);
   ```

   - 在模块的内存范围 `[module.base, module.base+module.size)` 内注册一个代码执行钩子。
   - 当模拟器执行到该范围内的任意指令时，会触发 `hook()` 方法。

2. **指令反汇编**

   ```java
   Capstone capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
   byte[] bytes = emulator.getBackend().mem_read(address, 4);
   Instruction[] disasm = capstone.disasm(bytes, 0);
   ```

   - 使用Capstone反汇编引擎，将当前指令地址（`address`）处的4字节机器码转换为可读的汇编指令。
   - **ARM64指令特性**：固定长度为4字节（Thumb模式为2/4字节混合，但此处明确指定`CS_MODE_ARM`，表明处理的是ARM模式指令）。

3. **输出格式**

   ```java
   System.out.printf("%x:%s %s\n", address - module.base, disasm[0].getMnemonic(), disasm[0].getOpStr());
   ```

   - 打印内容：
     - **相对偏移**：`address - module.base` 显示指令相对于模块基址的位置，方便定位代码段中的具体位置。
     - **助记符**：如 `BL`、`MOV` 等汇编指令名称。
     - **操作数**：指令的具体参数（如寄存器、立即数等）。

### 3.去除间接跳转

```assembly
CMP W8,W25
CSEL X9,X21,X25,CC
LDR X9,[X24,X9]
ADD X9,X9,X27
BR X9
```

![image-20250325114221585](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250325114221585.png)

1. **比较寄存器值**
   `CMP W8, W25`
   比较32位寄存器W8和W25的值，设置条件标志位。若W8 < W25，则进位标志位（C）被清除（CC条件成立）。
2. **条件选择偏移量**
   `CSEL X9, X21, X26, CC`
   根据CC条件（即W8 < W25），选择X21或X26的值赋给X9：
   - 若W8 < W25，选择X26的值。
   - 否则，选择X21的值。
3. **加载跳转地址**
   `LDR X9, [X24, X9]`
   以X24为基址，加上X9中的偏移量，从内存中加载一个64位地址到X9。这通常用于访问跳转表（如函数指针表）。
4. **调整地址**
   `ADD X9, X9, X27`
   将X27的值加到X9中，进一步调整目标地址。X27可能存储固定偏移或基址，用于定位最终跳转位置。
5. **跳转执行**
   `BR X9`
   无条件跳转到X9指向的地址，执行对应代码。

X27的值由MOV和MOVK分别赋值8位和16位的值，固定为 ==> 0x84FA7910

![image-20250326002335785](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250326002335785.png)

X24的值是一个数组

![image-20250326002507046](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250326002507046.png)

数组里面分别存了很多指令的地址，用于后续跳转使用

整体逻辑就是每次根据比较结果在数组中选择一个offset，然后用`offset + base`，得到真实的跳转地址

![image-20250326002701682](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250326002701682.png)

`CMP W8, W25`中的`W8`和`W25`的数值也是写死的

![image-20250326003109215](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250326003109215.png)

![image-20250326003124020](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250326003124020.png)

W8:0x3202B1A5

![image-20250326003207910](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250326003207910.png)

W25:0x58F48322

```assembly
CMP W8,W25
CSEL X9,X21,X25,CC
LDR X9,[X24,X9]
ADD X9,X9,X27
BR X9
```

以上方代码为例

当CC条件满足时，X21的值赋给X9作为一个offset，在`LDR X9,[X24,X9]`中使用X24的数组+偏移
根据CSEL的CC条件有两个分支如下：

`True  Addr:  (*(X24+X21) + X27)`

`False Addr: (*(X24+X25) + X27)`

那么我们可以根据CMP的结果使用`BCC / BLO`和`B`对True Addr和False Addr进行跳转

替换后的汇编如下

```assembly
CMP W8,W25
B.cond True Addr
LDR X9,[X24,X9]
ADD X9,X9,X27
B False addr
```

这样的间接跳转都变为了直接跳转，ida内就可以继续分析了，并且地址也没有变化，因为寄存器的值已知，我们只是其他将他计算出来再跳转而已。



#### **3.1目标** 

代码的核心目标是自动化修复一种特定的代码混淆技术。这种混淆使用 ARM64 的 `csel` (条件选择) 指令和 `br` (间接跳转) 指令来隐藏真实的跳转目标。

* **原始混淆代码:**

  ```assembly
  cmp w0, w1         ; 比较，设置条件标志 (e.g., EQ, NE)
  ; ... 可能有其他指令 ...
  csel x9, x20, x21, cond ; 如果条件eq为真, x9 = x20, 否则 x9 = x21 (x20/x21存有地址或地址的基址)
  ; ... 可能有其他指令, 可能会修改 x9 (e.g., ldr x9, [x24, x9]) ...
  br x9              ; 跳转到 x9 中的地址
  ```

* **修复后代码:**

  ```assembly
  cmp w0, w1         ; 保留比较
  ; ... 保留其他指令 ...
  b.cond <目标地址1>   ; Patch 1: 在原 csel 位置替换为条件跳转 (如果cond为真，跳到b1)
  ; ... 保留其他指令 ...
  b <目标地址2>      ; Patch 2: 在原 br 位置替换为无条件跳转 (对应cond为假，跳到b2)
  ```

为了安全准确地找到 `<目标地址1>` (T) 和 `<目标地址2>` (F)，代码采用了**双模拟器**的方法。

#### **3.2整体逻辑** 

1. **阶段 1: 发现与收集混淆特征 (使用主模拟器 `emulator`)**

   *   通过指令Hook 监控每一条执行的指令。
   *   识别 `csel` 指令，记录其**操作数、条件、地址**，以及**执行并保存它当前的寄存器状态**。
   *   识别 `br` 指令，并回溯查找与之关联的 `csel`（通过目标寄存器匹配）。
   *   当找到匹配的 `csel` 和 `br` 时，**不立即模拟**，而是创建一个 `SimulationTask`，包含 `csel` 的信息、`br` 的地址以及**关键的 `csel` 执行前的寄存器状态**。将任务添加到 `simulationTasks` 列表。

2. **阶段 2: 分支模拟与 Patch 生成 (使用临时模拟器 `tmpEmulator`)**

   *   主模拟器执行完毕后，遍历 `simulationTasks` 列表。
   *   对于每个任务：
       *   启动**临时模拟器 `tmpEmulator`**。
       *   **模拟真分支**: 恢复 `tmpEmulator` 到 `csel` 执行前的状态，强制 `csel` 目标寄存器为真分支，模拟执行直到原 `br` 位置，读取 `br` 寄存器的最终值得到 `b1 <True Addr>`。
       *   **模拟假分支**: **再次**恢复 `tmpEmulator` 到 `csel` 执行前的状态，强制 `csel` 目标寄存器为假分支，模拟执行直到原 `br` 位置，读取 `br` 寄存器的最终值得到 `b2 <False Addr>`。
       *   如果 `b1` 和 `b2` 有效且不同，则生成两条 Patch 指令（`b.cond b1` 和 `b b2`）并添加到 `patches` 列表。

3. **阶段 3: 应用 Patch**

   * 将 `patches` 列表中的`code`写入文件缓冲区的对应位置。

   * 将修改后的数据写入新的 .so-patch文件。

     

#### **3.3变量解释**

* `tmpEmulator`, `MainEmulator`: **临时模拟器**及其相关组件。用于安全地执行分支模拟。**为什么需要两个？** 避免在主模拟器运行时进行分支模拟可能导致的状态污染（寄存器、内存、Hook 状态被意外修改）。在写这段代码的时候尝试使用一个emulator，但很容易在patch后往下走的分支造成非法内存访问，所以我选择使用两个emu分别进行特征收集和patch执行，这样代码的健壮性会高很多。

  

* `insStack`: `Deque<InstructionContext>`。存储最近执行的指令及其执行前的寄存器状态。**为什么需要？** 当遇到 `br` 时，需要回溯查找之前的 `csel`，并且需要知道 `csel` 执行前的状态才能正确模拟。

  ```java
  private final Deque<InstructionContext> insStack = new ArrayDeque<>(128);
  ```

* `cselInfoMap`: `Map<Long, CselInfo>`。存储遇到的 `csel` 指令的详细信息，以其相对地址作为 Key，方便快速查找。

  ```java
  private final Map<Long, CselInfo> cselInfoMap = new HashMap<>();
  ```

  

1. **`DeOllvmBr_TwoEmus()`**:

   *   **初始化主模拟器 (`emulator`)**: 使用 `AndroidEmulatorBuilder` 配置并构建主模拟器。
   *   **初始化临时模拟器 (`tmpEmulator`)**: **重复**构建过程，创建第二个独立的模拟器实例。**关键在于**确保两者环境一致
   *   **基地址检查**: 检查 `module.base` 和 `tmpModule.base` 是否相同。这是一个重要的健全性检查。如果不同，所有传递给 `tmpEmulator` 的地址计算都需要做偏移调整。代码假设它们相同以简化。
   *   **设置 Hook**: 调用 `setupMainEmulatorHooks()` **只为主模拟器**设置代码 Hook。临时模拟器不需要全局 Hook。

2. **`setupMainEmulatorHooks()`**:

   *   为**主模拟器**添加代码 Hook (`CodeHook`)。
   *   Hook 的范围是配置的 `START_ADDR` 到 `END_ADDR`。
   *   `hook()` 方法: 当主模拟器执行到范围内的指令时被调用。
       *   检查地址是否已被 `patchedAddresses` 记录。
       *   如果未被 Patch，调用 `processInstruction` 处理该指令。
   *   `onAttach()` 方法: Hook 成功附加后回调，用于保存 `UnHook` 引用。

   ```java
       private void setupMainEmulatorHooks() {
           if (this.mainHook != null) {
               this.mainHook.unhook();
               this.mainHook = null;
           }
           System.out.println("  [Hook管理] 正在添加主模拟器 Hook...");
           emulator.getBackend().hook_add_new(new CodeHook() {
               @Override
               public void hook(Backend backend, long address, int size, Object user) {
                   // 主模拟器的 Hook 逻辑
                   long relativeAddr = address - module.base;
                   if (relativeAddr >= START_ADDR && relativeAddr <= END_ADDR) {
                       // 检查是否是已 Patch 地址 (基于最终 Patch 目标)
                       if (!patchedAddresses.contains(relativeAddr)) {
                           processInstruction(address, size, backend);
                       }
                   }
               }
   
               @Override
               public void onAttach(UnHook unHook) {
                   System.out.println("  [Hook管理] 主模拟器 Hook 已附加。");
                   DeOllvmBr_TwoEmus.this.mainHook = unHook;
               }
               @Override
               public void detach() {
                   System.out.println("  [Hook管理] 主模拟器 Hook 已分离。");
               }
           }, module.base + START_ADDR, module.base + END_ADDR, null);
       }
   ```

   

3. **`processInstruction()`**:

   *   由主模拟器的 Hook 调用。
   *   再次检查 `patchedAddresses`。
   *   `saveRegisters(backend)`: **保存当前指令执行前的寄存器状态**（重中之重
   *   反汇编当前地址的指令。
   *   创建 `InstructionContext` (指令 + 执行前状态)。
   *   将 `context` 压入 `insStack`。
   *   如果是 `csel`，调用 `handleConditionalSelect`。
   *   如果是 `br`，调用 `handleBranchInstruction`。

   ```java
       private void processInstruction(long absAddress, int size, Backend backend) {
           try {
               long relativeAddr = absAddress - module.base;
               if (patchedAddresses.contains(relativeAddr)) {
                   return;
               }
   
               List<Number> currentRegisters = saveRegisters(backend); // 保存主模拟器当前状态
               byte[] code = backend.mem_read(absAddress, size);
               Instruction[] insns = capstone.disasm(code, absAddress, 1);
               if (insns == null || insns.length == 0) return;
               Instruction ins = insns[0];
   
               InstructionContext context = new InstructionContext(relativeAddr, ins, currentRegisters);
               insStack.push(context);
               if (insStack.size() > 100) insStack.pollLast();
   
               System.out.printf("[MainEmu 执行] 0x%x (Rel: 0x%x): %s %s%n",
                       ins.getAddress(), relativeAddr, ins.getMnemonic(), ins.getOpStr());
   
               if ("csel".equalsIgnoreCase(ins.getMnemonic())) {
                   handleConditionalSelect(context);
               } else if ("br".equalsIgnoreCase(ins.getMnemonic())) {
                   // --- 不再调用模拟，而是检查并创建任务 ---
                   handleBranchInstruction(context);
               }
   
           } catch (Exception e) {
               System.err.printf("处理主模拟器指令错误 @ 0x%x: %s%n", absAddress, e.getMessage());
               e.printStackTrace();
           }
       }
   ```

   

4. **`handleConditionalSelect()`**:

   *   从传入的 `InstructionContext` 获取**执行前的寄存器状态**。
   *   读取条件为真/假时源寄存器的**值** (`trueSourceValue`, `falseSourceValue`)。
   *   创建 `CselInfo` 对象存储这些信息。
   *   将 `CselInfo` 存入 `cselInfoMap`。

   ```java
       private void handleConditionalSelect(InstructionContext currentContext) {
           Instruction ins = currentContext.instruction;
           long relativeAddr = currentContext.relativeAddr;
           String opStr = ins.getOpStr();
           String[] ops = opStr.split(",\\s*");
           if (ops.length < 4) return;
   
           String destReg = ops[0].trim();
           String trueReg = ops[1].trim();
           String falseReg = ops[2].trim();
           String condition = ops[3].trim().toLowerCase();
           List<Number> registersBeforeCsel = currentContext.registers; // CSEL 执行前的状态
   
           try {
               long trueSourceValue = getRegisterValue(trueReg, registersBeforeCsel);
               long falseSourceValue = getRegisterValue(falseReg, registersBeforeCsel);
               CselInfo info = new CselInfo(relativeAddr, destReg, condition, trueReg, falseReg, trueSourceValue, falseSourceValue);
               cselInfoMap.put(relativeAddr, info);
               System.out.printf("[MainEmu CSEL 发现] @0x%x: %s = %s ? %s(0x%x) : %s(0x%x). Cond: %s%n",
                       relativeAddr, destReg, condition, trueReg, trueSourceValue, falseReg, falseSourceValue, condition);
           } catch (IllegalArgumentException e) {
               System.err.printf("[MainEmu CSEL 错误] @0x%x: %s%n", relativeAddr, e.getMessage());
           }
       }
   ```

   

5. **`handleBranchInstruction()`**:

   * 解析 `br` 指令，获取目标寄存器名。

   * **回溯 `insStack`**: 查找最近执行的指令。

   * 检查历史指令是否是 `cselInfoMap` 中记录的 `csel`。

   * 如果找到 `csel`，并且其目标寄存器与 `br` 使用的寄存器匹配：

     *   **关键**: 调用 `findInstructionContext(prevRelativeAddr)` 从 `insStack` 中获取该 `csel` 对应的、包含**执行前状态**的 `InstructionContext`。
     *   创建 `SimulationTask` 对象，封装 `cselInfo`、`br` 的相对地址、以及最重要的 `registersBeforeCsel`。
     *   将 `task` 添加到 `simulationTasks` 列表。
     *   找到匹配后即返回，不再为同一个 `br` 查找更早的 `csel`。

     ```java
     private void handleBranchInstruction(InstructionContext brContext) {
         Instruction brIns = brContext.instruction;
         long brRelativeAddr = brContext.relativeAddr;
         String brReg = brIns.getOpStr().trim();
     
         System.out.printf("[MainEmu BR 发现] @0x%x: br %s. 查找匹配 CSEL...%n", brRelativeAddr, brReg);
     
         int searchDepth = 0;
         int maxSearchDepth = 30;
         Iterator<InstructionContext> it = insStack.iterator();
         if (it.hasNext()) it.next(); // Skip self
     
         while (it.hasNext() && searchDepth < maxSearchDepth) {
             InstructionContext prevContext = it.next();
             long prevRelativeAddr = prevContext.relativeAddr;
     
             if (cselInfoMap.containsKey(prevRelativeAddr)) {
                 CselInfo cselInfo = cselInfoMap.get(prevRelativeAddr);
                 if (cselInfo.destinationRegister.equalsIgnoreCase(brReg)) {
                     System.out.printf("  [MainEmu BR 匹配] CSEL @0x%x. 创建模拟任务...%n", prevRelativeAddr);
     
                     // --- 关键：获取 CSEL 执行前的状态 ---
                     InstructionContext cselContext = findInstructionContext(prevRelativeAddr);
                     if (cselContext == null) {
                         System.err.printf("  [MainEmu 错误] 无法找到 CSEL @0x%x 的上下文! 跳过任务创建.%n", prevRelativeAddr);
                         return; // 无法获取必要的状态
                     }
                     List<Number> registersBeforeCsel = cselContext.registers;
     
                     // 创建模拟任务
                     SimulationTask task = new SimulationTask(
                             cselInfo,
                             brRelativeAddr,
                             registersBeforeCsel,
                             module.base + cselInfo.cselAddress, // cselAbsAddr
                             module.base + brRelativeAddr      // brAbsAddr
                     );
                     simulationTasks.add(task);
                     System.out.printf("  [MainEmu 任务已添加] CSEL 0x%x -> BR 0x%x%n", cselInfo.cselAddress, brRelativeAddr);
     
                     // 可选：从 Map 中移除，防止一个 CSEL 被多个 BR 错误匹配
                     // cselInfoMap.remove(prevRelativeAddr);
                     return; 
                 }
             }
             searchDepth++;
         }
         // System.err.printf("[MainEmu BR 警告] @0x%x: 未找到 %s 的匹配 CSEL%n", brRelativeAddr, brReg);
     }
     ```

6. **`performSimulationsOnTmpEmu()`**:

   *   **协调临时模拟**: 接收一个 `SimulationTask`。
   *   获取 `tmpEmulator` 的后端接口 `tmpBackend`。
   *   调用 `performSingleSimulation(tmpBackend, task, true)` 模拟真分支，得到 `b1`。
   *   调用 `performSingleSimulation(tmpBackend, task, false)` 模拟假分支，得到 `b2`。
   *   比较 `b1` 和 `b2`。如果有效且不同，调用 `generatePatch` 生成 Patch。

   ```java
       private void performSimulationsOnTmpEmu(SimulationTask task) {
           System.out.printf("%n[TmpEmu] ===> 开始模拟任务: CSEL 0x%x -> BR 0x%x ===>%n",
                   task.cselInfo.cselAddress, task.brRelativeAddr);
   
           Backend tmpBackend = tmpEmulator.getBackend();
   
           // --- 模拟真分支 ---
           System.out.println("  [TmpEmu] --- 模拟真分支 (True) ---");
           long b1 = performSingleSimulation(tmpBackend, task, true);
           System.out.printf("  [TmpEmu] --- 真分支结果 b1 = 0x%x ---%n", b1);
   
           // --- 模拟假分支 ---
           System.out.println("  [TmpEmu] --- 模拟假分支 (False) ---");
           long b2 = performSingleSimulation(tmpBackend, task, false);
           System.out.printf("  [TmpEmu] --- 假分支结果 b2 = 0x%x ---%n", b2);
   
           // --- 处理结果 ---
           if (b1 != -1 && b2 != -1) { // 检查模拟是否成功
               if (b1 != b2) {
                   System.out.printf("  [TmpEmu 成功] 发现不同跳转目标: 真=0x%x, 假=0x%x. 生成 Patch.%n", b1, b2);
                   // 注意：generatePatch 需要绝对地址 b1, b2
                   generatePatch(task.cselInfo, task.brRelativeAddr, b1, b2);
               } else {
                   System.out.printf("  [TmpEmu 注意] 真假分支目标相同 (0x%x). 无需 Patch 或为其他模式.%n", b1);
               }
           } else {
               System.err.printf("  [TmpEmu 失败] 模拟未能确定跳转目标 (b1=0x%x, b2=0x%x).%n", b1, b2);
           }
           System.out.printf("[TmpEmu] <=== 模拟任务结束: CSEL 0x%x -> BR 0x%x <===%n",
                   task.cselInfo.cselAddress, task.brRelativeAddr);
       }
   ```

   

7. **`performSingleSimulation()`**:

   *   **核心模拟逻辑**: 在 `tmpEmulator` 上执行。
   *   `restoreRegisters(tmpBackend, task.registersBeforeCsel)`: **重置 `tmpEmulator` 状态**到 `csel` 执行前的样子。
   *   根据 `simulateTrueBranch` 标志，强制向 `csel` 的目标寄存器写入 `trueSourceValue` 或 `falseSourceValue`。
   *   设置 `tmpEmulator` 的 PC 到 `csel` 指令之后的位置 (`startPc`)。
   *   **添加临时 Hook**: 为 `tmpBackend` 添加一个临时的 `CodeHook`。这个 Hook 只关心执行是否到达了原始 `br` 的绝对地址 (`brAbsAddr`)。
       *   如果到达 `brAbsAddr`，Hook 读取 `br` 使用的寄存器的当前值（这就是模拟得到的跳转目标），存入 `resultHolder`，然后调用 `tmpBackend.emu_stop()` **停止当前这次模拟**，并设置 `stopped` 标志。
       *   使用 `UnHook[] tempHookHolder` 模式来在 `onAttach` 中获取 `UnHook` 引用。
   *   `tmpBackend.emu_start(...)`: **启动模拟执行**。从 `startPc` 开始，最多执行到 `brAbsAddr + 8`（留一点余量），并设置指令数超时限制。
   *   获取 `resultHolder` 中的结果（模拟得到的绝对跳转地址）。
   *   **`finally` 块**: 确保移除临时添加的 Hook (`tempHookHolder[0].unhook()`)，清理现场。
   *   返回模拟得到的跳转目标地址 `targetAbsAddress` (或 -1 表示失败)。

   

8. **`generatePatch()`**:

   *   接收 `cselInfo`、`brRelativeAddr` 和模拟得到的两个**绝对**目标地址 `b1`, `b2`。
   *   计算两个新跳转指令的**相对偏移量**:
       *   `b.cond b1`: 替换 `csel`。PC 是 `csel` 地址，目标是 `b1`。偏移 = `b1 - cselAbsoluteAddr`。
       *   `b b2`: 替换 `br`。PC 是 `br` 地址，目标是 `b2`。偏移 = `b2 - brAbsoluteAddr`。
   *   创建两个 `Patch` 对象，分别对应 `csel` 和 `br` 的位置。
   *   将 `cselRelativeAddr` 和 `brRelativeAddr` 添加到 `patchedAddresses`。

   ```java
   private void generatePatch(CselInfo cselInfo, long brRelativeAddr, long trueTargetAbsAddress, long falseTargetAbsAddress) {
       long cselRelativeAddr = cselInfo.cselAddress;
   
       // 检查地址是否已被 Patch
       if (patchedAddresses.contains(cselRelativeAddr) || patchedAddresses.contains(brRelativeAddr)) {
           System.out.printf("  [Patch 跳过] 地址 0x%x 或 0x%x 已标记 Patch.%n", cselRelativeAddr, brRelativeAddr);
           return;
       }
       if (cselRelativeAddr == brRelativeAddr || Math.abs(cselRelativeAddr - brRelativeAddr) < 4) {
           System.err.printf("  [Patch 错误/警告] CSEL (0x%x) 和 BR (0x%x) 地址相同或重叠.%n", cselRelativeAddr, brRelativeAddr);
           return; // 避免覆盖
       }
   
       try {
           // 获取绝对地址 (基于主模块)
           long cselAbsoluteAddr = module.base + cselRelativeAddr;
           long brAbsoluteAddr = module.base + brRelativeAddr;
   
           // Patch 1: 条件跳转 @ CSEL 位置 (b.cond b1)
           long offset1 = trueTargetAbsAddress - cselAbsoluteAddr;
           String condJumpAsm = String.format("b.%s #0x%x", cselInfo.condition.toLowerCase(), offset1);
   
           // Patch 2: 无条件跳转 @ BR 位置 (b b2)
           long offset2 = falseTargetAbsAddress - brAbsoluteAddr;
           String uncondJumpAsm = String.format("b #0x%x", offset2);
   
           // 范围检查 (可选)
           // ... (可以保留之前的范围检查代码，使用 offset1 和 offset2) ...
   
           // 添加 Patch (使用相对地址)
           patches.add(new Patch(cselRelativeAddr, condJumpAsm, trueTargetAbsAddress));
           patches.add(new Patch(brRelativeAddr, uncondJumpAsm, falseTargetAbsAddress));
   
           // 标记地址已 Patch
           patchedAddresses.add(cselRelativeAddr);
           patchedAddresses.add(brRelativeAddr);
   
           System.out.printf("    [Patch 已生成] @CSEL 0x%x: %s (目标: 0x%x)%n", cselRelativeAddr, condJumpAsm, trueTargetAbsAddress);
           System.out.printf("                   @BR   0x%x: %s (目标: 0x%x)%n", brRelativeAddr, uncondJumpAsm, falseTargetAbsAddress);
   
       } catch (Exception e) {
           System.err.printf("  [Patch 生成错误] @CSEL 0x%x -> BR 0x%x: %s%n", cselRelativeAddr, brRelativeAddr, e.getMessage());
           e.printStackTrace();
       }
   }
   ```

9. **辅助方法**:

   *   `saveRegisters`, `restoreRegisters`: 保存/恢复 ARM64 通用寄存器状态。
   *   `getRegisterValue`: 从保存的状态列表中读取寄存器值。
   *   `getRegisterId`: 将寄存器名称字符串转为 Unicorn 的常量 ID。
   *   `findInstructionContext`: 在 `insStack` 中根据地址查找对应的上下文。
   *   `bytesToHex`: 格式化输出。

   

   

### **4.总结**

*   **隔离性**: 临时模拟器 `tmpEmulator` 的状态在每次 `performSingleSimulation` 开始时都被精确重置到 `csel` 执行前的状态。这避免了主模拟器复杂状态对分支模拟的干扰。
*   **健壮性**: 减少了状态管理出错的可能性。在单个模拟器方案中，模拟执行的过程如果出错，可能导致主模拟流程崩溃或后续分析错误。双模拟器方案中，临时模拟器的崩溃不影响主模拟器。
*   **清晰度**: 逻辑更分明，主模拟器负责发现，临时模拟器负责验证。

#### 完整代码

```java
import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;
import unicorn.UnicornConst;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

// 修改类名以反映新方法
public class DeOllvmBr_TwoEmus {

    // --- 主模拟器实例 ---
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DalvikModule dm;
    private final Module module;

    // --- 临时模拟器实例 ---
    private final AndroidEmulator tmpEmulator;
    private final VM tmpVm;
    private final Module tmpModule; // 临时模拟器加载的模块

    // --- 配置 ---
    private static final String INPUT_SO = "D:\\unidbg\\unidbg-android\\src\\test\\resources\\AntiOllvm\\libtprt.so";
    private static final String OUTPUT_SO = "D:\\unidbg\\unidbg-android\\src\\test\\resources\\AntiOllvm\\libtprt-patch.so";
    private static final long START_ADDR = 0x87014L;
    private static final long END_ADDR = 0x87730L;
    private static final long SIMULATION_TIMEOUT_INSTRUCTIONS = 100;

    // --- 动态分析数据结构 ---
    private final Deque<InstructionContext> insStack = new ArrayDeque<>(128);
    private final Map<Long, CselInfo> cselInfoMap = new HashMap<>();
    // --- 新增：存储待模拟的任务 ---
    private final List<SimulationTask> simulationTasks = new ArrayList<>();
    private final List<Patch> patches = new ArrayList<>();
    private final Set<Long> patchedAddresses = new HashSet<>(); // 记录 Patch 应用的相对地址

    // --- Capstone & Keystone 实例 ---
    private final Capstone capstone;
    private final Keystone keystone;

    // --- 模拟控制 ---
    private UnHook mainHook = null; // 主模拟器的 Hook

    public DeOllvmBr_TwoEmus() throws IOException {
        // --- 初始化主模拟器 ---
        System.out.println("[初始化] 创建主模拟器 (emulator)...");
        emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.deobf.main")
                .build(); // 直接调用 build() 并赋值
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setVerbose(false); // 主模拟器可以不那么啰嗦

        // --- 初始化临时模拟器 ---
        System.out.println("[初始化] 创建临时模拟器 (tmpEmulator)...");
        tmpEmulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.deobf.tmp")
                .build(); // 直接调用 build() 并赋值
        Memory tmpMemory = tmpEmulator.getMemory();
        // 使用相同的解析器设置，确保环境一致性
        tmpMemory.setLibraryResolver(new AndroidResolver(23));
        tmpVm = tmpEmulator.createDalvikVM();
        tmpVm.setVerbose(false); // 临时模拟器也可以安静点

        // --- 加载 SO 到两个模拟器 ---
        File soFile = new File(INPUT_SO);
        if (!soFile.exists()) {
            throw new IOException("输入 SO 文件未找到: " + INPUT_SO);
        }
        System.out.println("[初始化] 加载 SO 到主模拟器...");
        dm = vm.loadLibrary(soFile, false); // 主 Dalvik 模块
        module = dm.getModule();             // 主模块

        System.out.println("[初始化] 加载 SO 到临时模拟器...");
        // 临时模拟器也需要加载库，但我们不需要它的 DalvikModule 引用，只需要 Module
        // 注意：这里假设两个模拟器会将 SO 加载到相同的基地址。
        // 如果基地址不同，后续地址计算需要考虑 tmpModule.base
        DalvikModule tmpDm = tmpVm.loadLibrary(soFile, false);
        tmpModule = tmpDm.getModule();

        // 验证基地址是否一致（推荐检查）
        if (module.base != tmpModule.base) {
            System.err.printf("[警告] 主模块基址 (0x%x) 与临时模块基址 (0x%x) 不同！地址转换可能需要调整！%n",
                    module.base, tmpModule.base);
            // 如果不同，后续所有传递给 tmpEmulator 的地址都需要从 module.base 转换到 tmpModule.base
            // 例如: tmpAbsAddr = addr - module.base + tmpModule.base
            // 为了简化，以下代码假设基地址相同。
        }

        // --- 初始化工具 ---
        capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
        capstone.setDetail(true);
        keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);

        System.out.printf("[主模块] %s, 基址: 0x%x, 大小: 0x%x%n", module.name, module.base, module.size);
        System.out.printf("[临时模块] %s, 基址: 0x%x, 大小: 0x%x%n", tmpModule.name, tmpModule.base, tmpModule.size);
        System.out.printf("Hook 范围 (主模拟器绝对地址): 0x%x - 0x%x%n", module.base + START_ADDR, module.base + END_ADDR);

        // --- 设置 Hook (仅在主模拟器上) ---
        setupMainEmulatorHooks();
    }

    // 设置主模拟器的 Hook
    private void setupMainEmulatorHooks() {
        if (this.mainHook != null) {
            this.mainHook.unhook();
            this.mainHook = null;
        }
        System.out.println("  [Hook管理] 正在添加主模拟器 Hook...");
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                // 主模拟器的 Hook 逻辑
                long relativeAddr = address - module.base;
                if (relativeAddr >= START_ADDR && relativeAddr <= END_ADDR) {
                    // 检查是否是已 Patch 地址 (基于最终 Patch 目标)
                    if (!patchedAddresses.contains(relativeAddr)) {
                        processInstruction(address, size, backend);
                    }
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("  [Hook管理] 主模拟器 Hook 已附加。");
                DeOllvmBr_TwoEmus.this.mainHook = unHook;
            }

            @Override
            public void detach() {
                System.out.println("  [Hook管理] 主模拟器 Hook 已分离。");
            }
        }, module.base + START_ADDR, module.base + END_ADDR, null);
    }

    // 处理主模拟器中的指令
    private void processInstruction(long absAddress, int size, Backend backend) {
        try {
            long relativeAddr = absAddress - module.base;
            if (patchedAddresses.contains(relativeAddr)) { // 再次检查，以防万一
                return;
            }

            List<Number> currentRegisters = saveRegisters(backend); // 保存主模拟器当前状态
            byte[] code = backend.mem_read(absAddress, size);
            Instruction[] insns = capstone.disasm(code, absAddress, 1);

            if (insns == null || insns.length == 0) return;
            Instruction ins = insns[0];

            InstructionContext context = new InstructionContext(relativeAddr, ins, currentRegisters);
            insStack.push(context);
            if (insStack.size() > 100) insStack.pollLast();

            System.out.printf("[MainEmu 执行] 0x%x (Rel: 0x%x): %s %s%n",
                    ins.getAddress(), relativeAddr, ins.getMnemonic(), ins.getOpStr());

            if ("csel".equalsIgnoreCase(ins.getMnemonic())) {
                handleConditionalSelect(context);
            } else if ("br".equalsIgnoreCase(ins.getMnemonic())) {
                // --- 修改点：不再调用模拟，而是检查并创建任务 ---
                handleBranchInstruction(context);
            }

        } catch (Exception e) {
            System.err.printf("处理主模拟器指令错误 @ 0x%x: %s%n", absAddress, e.getMessage());
            e.printStackTrace();
        }
    }

    // 处理 CSEL (与之前类似，仅记录信息)
    private void handleConditionalSelect(InstructionContext currentContext) {
        Instruction ins = currentContext.instruction;
        long relativeAddr = currentContext.relativeAddr;
        String opStr = ins.getOpStr();
        String[] ops = opStr.split(",\\s*");
        if (ops.length < 4) return;

        String destReg = ops[0].trim();
        String trueReg = ops[1].trim();
        String falseReg = ops[2].trim();
        String condition = ops[3].trim().toLowerCase();
        List<Number> registersBeforeCsel = currentContext.registers; // CSEL 执行前的状态

        try {
            long trueSourceValue = getRegisterValue(trueReg, registersBeforeCsel);
            long falseSourceValue = getRegisterValue(falseReg, registersBeforeCsel);
            CselInfo info = new CselInfo(relativeAddr, destReg, condition, trueReg, falseReg, trueSourceValue, falseSourceValue);
            cselInfoMap.put(relativeAddr, info);
            System.out.printf("[MainEmu CSEL 发现] @0x%x: %s = %s ? %s(0x%x) : %s(0x%x). Cond: %s%n",
                    relativeAddr, destReg, condition, trueReg, trueSourceValue, falseReg, falseSourceValue, condition);
        } catch (IllegalArgumentException e) {
            System.err.printf("[MainEmu CSEL 错误] @0x%x: %s%n", relativeAddr, e.getMessage());
        }
    }

    // 处理 BR (仅查找匹配 CSEL 并创建任务)
    private void handleBranchInstruction(InstructionContext brContext) {
        Instruction brIns = brContext.instruction;
        long brRelativeAddr = brContext.relativeAddr;
        String brReg = brIns.getOpStr().trim();

        System.out.printf("[MainEmu BR 发现] @0x%x: br %s. 查找匹配 CSEL...%n", brRelativeAddr, brReg);

        int searchDepth = 0;
        int maxSearchDepth = 30;
        Iterator<InstructionContext> it = insStack.iterator();
        if (it.hasNext()) it.next(); // Skip self

        while (it.hasNext() && searchDepth < maxSearchDepth) {
            InstructionContext prevContext = it.next();
            long prevRelativeAddr = prevContext.relativeAddr;

            if (cselInfoMap.containsKey(prevRelativeAddr)) {
                CselInfo cselInfo = cselInfoMap.get(prevRelativeAddr);
                if (cselInfo.destinationRegister.equalsIgnoreCase(brReg)) {
                    System.out.printf("  [MainEmu BR 匹配] CSEL @0x%x. 创建模拟任务...%n", prevRelativeAddr);

                    // --- 关键：获取 CSEL 执行前的状态 ---
                    InstructionContext cselContext = findInstructionContext(prevRelativeAddr);
                    if (cselContext == null) {
                        System.err.printf("  [MainEmu 错误] 无法找到 CSEL @0x%x 的上下文! 跳过任务创建.%n", prevRelativeAddr);
                        return; // 无法获取必要的状态
                    }
                    List<Number> registersBeforeCsel = cselContext.registers;

                    // 创建模拟任务
                    SimulationTask task = new SimulationTask(
                            cselInfo,
                            brRelativeAddr,
                            registersBeforeCsel,
                            module.base + cselInfo.cselAddress, // cselAbsAddr
                            module.base + brRelativeAddr      // brAbsAddr
                    );
                    simulationTasks.add(task);
                    System.out.printf("  [MainEmu 任务已添加] CSEL 0x%x -> BR 0x%x%n", cselInfo.cselAddress, brRelativeAddr);

                    // 可选：从 Map 中移除，防止一个 CSEL 被多个 BR 错误匹配
                    // cselInfoMap.remove(prevRelativeAddr);
                    return; // 找到匹配，停止搜索
                }
            }
            searchDepth++;
        }
        // System.err.printf("[MainEmu BR 警告] @0x%x: 未找到 %s 的匹配 CSEL%n", brRelativeAddr, brReg);
    }

    // --- 新增：在临时模拟器上执行模拟 ---
    /**
     * 使用临时模拟器执行真假两个分支的模拟。
     * @param task 包含 CSEL 信息、BR 地址和 CSEL 前状态的任务
     */
    private void performSimulationsOnTmpEmu(SimulationTask task) {
        System.out.printf("%n[TmpEmu] ===> 开始模拟任务: CSEL 0x%x -> BR 0x%x ===>%n",
                task.cselInfo.cselAddress, task.brRelativeAddr);

        Backend tmpBackend = tmpEmulator.getBackend();

        // --- 模拟真分支 ---
        System.out.println("  [TmpEmu] --- 模拟真分支 (True) ---");
        long b1 = performSingleSimulation(tmpBackend, task, true);
        System.out.printf("  [TmpEmu] --- 真分支结果 b1 = 0x%x ---%n", b1);

        // --- 模拟假分支 ---
        System.out.println("  [TmpEmu] --- 模拟假分支 (False) ---");
        long b2 = performSingleSimulation(tmpBackend, task, false);
        System.out.printf("  [TmpEmu] --- 假分支结果 b2 = 0x%x ---%n", b2);

        // --- 处理结果 ---
        if (b1 != -1 && b2 != -1) { // 检查模拟是否成功
            if (b1 != b2) {
                System.out.printf("  [TmpEmu 成功] 发现不同跳转目标: 真=0x%x, 假=0x%x. 生成 Patch.%n", b1, b2);
                // 注意：generatePatch 需要绝对地址 b1, b2
                generatePatch(task.cselInfo, task.brRelativeAddr, b1, b2);
            } else {
                System.out.printf("  [TmpEmu 注意] 真假分支目标相同 (0x%x). 无需 Patch 或为其他模式.%n", b1);
            }
        } else {
            System.err.printf("  [TmpEmu 失败] 模拟未能确定跳转目标 (b1=0x%x, b2=0x%x).%n", b1, b2);
        }
        System.out.printf("[TmpEmu] <=== 模拟任务结束: CSEL 0x%x -> BR 0x%x <===%n",
                task.cselInfo.cselAddress, task.brRelativeAddr);
    }

    /**
     * 在临时模拟器上执行单次模拟（真或假）。
     * @param tmpBackend 临时模拟器的后端
     * @param task       模拟任务信息
     * @param simulateTrueBranch 是否模拟真分支
     * @return 模拟得到的 BR 寄存器的绝对地址值，失败返回 -1
     */
    private long performSingleSimulation(Backend tmpBackend, SimulationTask task, boolean simulateTrueBranch) {
        long targetAbsAddress = -1;
        final UnHook[] tempHookHolder = { null }; // 用于停止模拟的 Hook

        try {
            // 1. 恢复 tmpEmulator 状态到 CSEL 执行前
            System.out.println("    [TmpEmu] 恢复寄存器状态至 CSEL 之前...");
            restoreRegisters(tmpBackend, task.registersBeforeCsel);

            // 2. 强制修改 CSEL 目标寄存器的值
            long valueToForce = simulateTrueBranch ? task.cselInfo.trueSourceValue : task.cselInfo.falseSourceValue;
            int destRegId = getRegisterId(task.cselInfo.destinationRegister);
            if (destRegId == -1) {
                System.err.printf("    [TmpEmu 错误] 无法识别 CSEL 目标寄存器: %s%n", task.cselInfo.destinationRegister);
                return -1;
            }
            tmpBackend.reg_write(destRegId, valueToForce);
            System.out.printf("    [TmpEmu] 强制设置 %s = 0x%x (%s 分支)%n",
                    task.cselInfo.destinationRegister, valueToForce, simulateTrueBranch ? "真" : "假");

            // 3. 设置起始 PC (CSEL 指令之后)
            // 假设基地址相同，直接使用 task 中的绝对地址
            long startPc = task.cselAbsoluteAddr + 4;
            tmpBackend.reg_write(Arm64Const.UC_ARM64_REG_PC, startPc);
            System.out.printf("    [TmpEmu] 设置起始 PC = 0x%x%n", startPc);

            // 4. 设置临时 Hook 以在 BR 指令处停止
            final long[] resultHolder = {-1L};
            final boolean[] stopped = {false};
            long brAbsAddr = task.brAbsoluteAddr; // 目标停止地址

            tmpBackend.hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    if (address == brAbsAddr) {
                        System.out.printf("      [TmpEmu Hook] 到达目标 BR 地址 0x%x%n", address);
                        try {
                            int brRegId = getRegisterId(task.cselInfo.destinationRegister); // BR 使用的寄存器
                            if (brRegId != -1) {
                                resultHolder[0] = backend.reg_read(brRegId).longValue(); // 读取绝对地址
                            } else {
                                System.err.printf("      [TmpEmu Hook 错误] 无法识别 BR 寄存器: %s%n", task.cselInfo.destinationRegister);
                            }
                        } catch (Exception e) {
                            System.err.printf("      [TmpEmu Hook 错误] 读取 BR 寄存器值时出错: %s%n", e.getMessage());
                        }
                        backend.emu_stop();
                        stopped[0] = true;
                        System.out.printf("      [TmpEmu Hook] 模拟停止. 读取到 %s = 0x%x%n", task.cselInfo.destinationRegister, resultHolder[0]);
                    }
                }
                @Override public void onAttach(UnHook unHook) { tempHookHolder[0] = unHook; }
                @Override public void detach() {}
            }, startPc, brAbsAddr + 4, null); // Hook 范围

            // 5. 开始模拟执行
            System.out.printf("    [TmpEmu] 开始执行从 0x%x 到 0x%x (最多 %d 指令)%n", startPc, brAbsAddr, SIMULATION_TIMEOUT_INSTRUCTIONS);
            try {
                // 运行模拟，结束地址设为 BR 地址之后一点点，超时时间设为 SIMULATION_TIMEOUT_INSTRUCTIONS
                tmpBackend.emu_start(startPc, brAbsAddr + 8, 0, SIMULATION_TIMEOUT_INSTRUCTIONS);
            } catch (Exception emuEx) {
                if (!stopped[0]) { // 如果不是被我们的 Hook 停止的
                    System.err.printf("    [TmpEmu 执行异常] emu_start 失败或超时: %s%n", emuEx.getMessage());
                    try {
                        long currentPc = tmpBackend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                        System.err.printf("    [TmpEmu 执行异常] 模拟停止在 PC=0x%x%n", currentPc);
                    } catch (Exception pcEx) { /* ignore */ }
                } else {
                    System.out.println("    [TmpEmu] emu_start 正常停止 (由 Hook 触发)。");
                }
            }

            // 6. 获取结果 (绝对地址)
            targetAbsAddress = resultHolder[0];

        } catch (Exception e) {
            System.err.printf("    [TmpEmu 模拟严重错误]: %s%n", e.getMessage());
            e.printStackTrace();
            targetAbsAddress = -1;
        } finally {
            // 7. 清理临时 Hook
            if (tempHookHolder[0] != null) {
                tempHookHolder[0].unhook();
            }
        }
        return targetAbsAddress;
    }


    /**
     * 生成 B.cond 和 B 指令的 Patch 信息。
     * B.cond 替换原始 CSEL 指令。
     * B 替换原始 BR 指令。
     * @param cselInfo 匹配到的 CSEL 指令信息
     * @param brRelativeAddr 原始 BR 指令的相对地址
     * @param trueTargetAbsAddress 模拟得到的真分支目标绝对地址 (b1)
     * @param falseTargetAbsAddress 模拟得到的假分支目标绝对地址 (b2)
     */
    private void generatePatch(CselInfo cselInfo, long brRelativeAddr, long trueTargetAbsAddress, long falseTargetAbsAddress) {
        long cselRelativeAddr = cselInfo.cselAddress;

        // 检查地址是否已被 Patch
        if (patchedAddresses.contains(cselRelativeAddr) || patchedAddresses.contains(brRelativeAddr)) {
            System.out.printf("  [Patch 跳过] 地址 0x%x 或 0x%x 已标记 Patch.%n", cselRelativeAddr, brRelativeAddr);
            return;
        }
        if (cselRelativeAddr == brRelativeAddr || Math.abs(cselRelativeAddr - brRelativeAddr) < 4) {
            System.err.printf("  [Patch 错误/警告] CSEL (0x%x) 和 BR (0x%x) 地址相同或重叠.%n", cselRelativeAddr, brRelativeAddr);
            return; // 避免覆盖
        }

        try {
            long cselAbsoluteAddr = module.base + cselRelativeAddr;
            long brAbsoluteAddr = module.base + brRelativeAddr;

            // Patch 1: 条件跳转 @ CSEL 位置 (b.cond b1)
            long offset1 = trueTargetAbsAddress - cselAbsoluteAddr;
            String condJumpAsm = String.format("b.%s #0x%x", cselInfo.condition.toLowerCase(), offset1);

            // Patch 2: 无条件跳转 @ BR 位置 (b b2)
            long offset2 = falseTargetAbsAddress - brAbsoluteAddr;
            String uncondJumpAsm = String.format("b #0x%x", offset2);

            // 添加 Patch (使用相对地址)
            patches.add(new Patch(cselRelativeAddr, condJumpAsm, trueTargetAbsAddress));
            patches.add(new Patch(brRelativeAddr, uncondJumpAsm, falseTargetAbsAddress));

            // 标记地址已 Patch
            patchedAddresses.add(cselRelativeAddr);
            patchedAddresses.add(brRelativeAddr);

            System.out.printf("    [Patch 已生成] @CSEL 0x%x: %s (目标: 0x%x)%n", cselRelativeAddr, condJumpAsm, trueTargetAbsAddress);
            System.out.printf("                   @BR   0x%x: %s (目标: 0x%x)%n", brRelativeAddr, uncondJumpAsm, falseTargetAbsAddress);

        } catch (Exception e) {
            System.err.printf("  [Patch 生成错误] @CSEL 0x%x -> BR 0x%x: %s%n", cselRelativeAddr, brRelativeAddr, e.getMessage());
            e.printStackTrace();
        }
    }


    private List<Number> saveRegisters(Backend backend) {
        List<Number> regs = new ArrayList<>(32);
        for (int i = Arm64Const.UC_ARM64_REG_X0; i <= Arm64Const.UC_ARM64_REG_X28; i++) regs.add(backend.reg_read(i));
        regs.add(backend.reg_read(Arm64Const.UC_ARM64_REG_FP)); regs.add(backend.reg_read(Arm64Const.UC_ARM64_REG_LR)); regs.add(backend.reg_read(Arm64Const.UC_ARM64_REG_SP));
        return regs;
    }
    private void restoreRegisters(Backend backend, List<Number> regs) {
        if (regs == null || regs.size() < 32) { System.err.println("[错误] 尝试恢复无效的寄存器列表!"); return; }
        for (int i = Arm64Const.UC_ARM64_REG_X0; i <= Arm64Const.UC_ARM64_REG_X28; i++) backend.reg_write(i, regs.get(i - Arm64Const.UC_ARM64_REG_X0));
        backend.reg_write(Arm64Const.UC_ARM64_REG_FP, regs.get(29)); backend.reg_write(Arm64Const.UC_ARM64_REG_LR, regs.get(30)); backend.reg_write(Arm64Const.UC_ARM64_REG_SP, regs.get(31));
    }
    private long getRegisterValue(String reg, List<Number> ctx) {
        if (ctx == null || ctx.size() < 32) throw new IllegalArgumentException("无效的寄存器上下文列表");
        reg = reg.toLowerCase().trim();
        if ("xzr".equals(reg) || "wzr".equals(reg)) return 0L;
        int regId = getRegisterId(reg);
        if (regId != -1) {
            int index = -1;
            if (regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) index = regId - Arm64Const.UC_ARM64_REG_X0;
            else if (regId == Arm64Const.UC_ARM64_REG_FP) index = 29;
            else if (regId == Arm64Const.UC_ARM64_REG_LR) index = 30;
            else if (regId == Arm64Const.UC_ARM64_REG_SP) index = 31;
            if (index != -1 && index < ctx.size()) {
                long value = ctx.get(index).longValue();
                if (reg.startsWith("w") && !"wzr".equals(reg) && !"wsp".equals(reg)) return value & 0xFFFFFFFFL;
                return value;
            }
        }
        throw new IllegalArgumentException("不支持或无效的寄存器名称: " + reg);
    }
    private int getRegisterId(String reg) { /* ... 不变 ... */
        reg = reg.toLowerCase().trim();
        switch (reg) {
            case "x0": return Arm64Const.UC_ARM64_REG_X0; case "x1": return Arm64Const.UC_ARM64_REG_X1; case "x2": return Arm64Const.UC_ARM64_REG_X2; case "x3": return Arm64Const.UC_ARM64_REG_X3; case "x4": return Arm64Const.UC_ARM64_REG_X4; case "x5": return Arm64Const.UC_ARM64_REG_X5; case "x6": return Arm64Const.UC_ARM64_REG_X6; case "x7": return Arm64Const.UC_ARM64_REG_X7; case "x8": return Arm64Const.UC_ARM64_REG_X8; case "x9": return Arm64Const.UC_ARM64_REG_X9; case "x10": return Arm64Const.UC_ARM64_REG_X10; case "x11": return Arm64Const.UC_ARM64_REG_X11; case "x12": return Arm64Const.UC_ARM64_REG_X12; case "x13": return Arm64Const.UC_ARM64_REG_X13; case "x14": return Arm64Const.UC_ARM64_REG_X14; case "x15": return Arm64Const.UC_ARM64_REG_X15; case "x16": return Arm64Const.UC_ARM64_REG_X16; case "x17": return Arm64Const.UC_ARM64_REG_X17; case "x18": return Arm64Const.UC_ARM64_REG_X18; case "x19": return Arm64Const.UC_ARM64_REG_X19; case "x20": return Arm64Const.UC_ARM64_REG_X20; case "x21": return Arm64Const.UC_ARM64_REG_X21; case "x22": return Arm64Const.UC_ARM64_REG_X22; case "x23": return Arm64Const.UC_ARM64_REG_X23; case "x24": return Arm64Const.UC_ARM64_REG_X24; case "x25": return Arm64Const.UC_ARM64_REG_X25; case "x26": return Arm64Const.UC_ARM64_REG_X26; case "x27": return Arm64Const.UC_ARM64_REG_X27; case "x28": return Arm64Const.UC_ARM64_REG_X28; case "x29": case "fp": return Arm64Const.UC_ARM64_REG_FP; case "x30": case "lr": return Arm64Const.UC_ARM64_REG_LR; case "sp": return Arm64Const.UC_ARM64_REG_SP; case "pc": return Arm64Const.UC_ARM64_REG_PC; case "xzr": return Arm64Const.UC_ARM64_REG_XZR;
            case "w0": return Arm64Const.UC_ARM64_REG_X0; case "w1": return Arm64Const.UC_ARM64_REG_X1; case "w2": return Arm64Const.UC_ARM64_REG_X2; case "w3": return Arm64Const.UC_ARM64_REG_X3; case "w4": return Arm64Const.UC_ARM64_REG_X4; case "w5": return Arm64Const.UC_ARM64_REG_X5; case "w6": return Arm64Const.UC_ARM64_REG_X6; case "w7": return Arm64Const.UC_ARM64_REG_X7; case "w8": return Arm64Const.UC_ARM64_REG_X8; case "w9": return Arm64Const.UC_ARM64_REG_X9; case "w10": return Arm64Const.UC_ARM64_REG_X10; case "w11": return Arm64Const.UC_ARM64_REG_X11; case "w12": return Arm64Const.UC_ARM64_REG_X12; case "w13": return Arm64Const.UC_ARM64_REG_X13; case "w14": return Arm64Const.UC_ARM64_REG_X14; case "w15": return Arm64Const.UC_ARM64_REG_X15; case "w16": return Arm64Const.UC_ARM64_REG_X16; case "w17": return Arm64Const.UC_ARM64_REG_X17; case "w18": return Arm64Const.UC_ARM64_REG_X18; case "w19": return Arm64Const.UC_ARM64_REG_X19; case "w20": return Arm64Const.UC_ARM64_REG_X20; case "w21": return Arm64Const.UC_ARM64_REG_X21; case "w22": return Arm64Const.UC_ARM64_REG_X22; case "w23": return Arm64Const.UC_ARM64_REG_X23; case "w24": return Arm64Const.UC_ARM64_REG_X24; case "w25": return Arm64Const.UC_ARM64_REG_X25; case "w26": return Arm64Const.UC_ARM64_REG_X26; case "w27": return Arm64Const.UC_ARM64_REG_X27; case "w28": return Arm64Const.UC_ARM64_REG_X28; case "w29": return Arm64Const.UC_ARM64_REG_FP; case "w30": return Arm64Const.UC_ARM64_REG_LR; case "wzr": return Arm64Const.UC_ARM64_REG_WZR;
            default: return -1;
        }
    }
    private InstructionContext findInstructionContext(long relativeAddr) { /* ... 不变 ... */
        for (InstructionContext ctx : insStack) if (ctx.relativeAddr == relativeAddr) return ctx; return null;
    }
    private static String bytesToHex(byte[] bytes) { /* ... 不变 ... */
        if (bytes == null) return "null"; StringBuilder sb = new StringBuilder(); for (byte b : bytes) sb.append(String.format("%02X ", b)); return sb.toString().trim();
    }

    // --- 应用 Patch (不变) ---
    private void applyPatches() {
        if (patches.isEmpty()) { System.out.println("没有生成任何 Patch。"); return; }
        System.out.printf("%n准备应用 %d 个 Patch 到 %s...%n", patches.size(), OUTPUT_SO);
        File inputFile = new File(INPUT_SO); File outputFile = new File(OUTPUT_SO);
        try (FileInputStream fis = new FileInputStream(inputFile); FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] buffer = fis.readAllBytes(); int appliedCount = 0;
            for (Patch p : patches) {
                if (p.address < 0 || p.address + 4 > buffer.length) { System.err.printf("跳过 Patch: 地址 0x%x 超出文件范围 (0x%x)%n", p.address, buffer.length); continue; }
                try {
                    long absPatchAddr = module.base + p.address; // 使用主模块基址计算汇编地址
                    KeystoneEncoded encoded = keystone.assemble(p.instruction); // 提供汇编地址
                    byte[] machineCode = encoded.getMachineCode();
                    if (machineCode == null || machineCode.length != 4) { System.err.printf("Keystone 错误: 汇编 '%s' 失败或长度不正确 (%d bytes) @ 0x%x (Abs: 0x%x)%n", p.instruction, machineCode != null ? machineCode.length : 0, p.address, absPatchAddr); continue; }
                    System.arraycopy(machineCode, 0, buffer, (int) p.address, 4);
                    System.out.printf("  已应用 @0x%x: %s -> %s (模拟目标: 0x%x)%n", p.address, p.instruction, bytesToHex(machineCode), p.targetAddress);
                    appliedCount++;
                } catch (Exception ke) { System.err.printf("Keystone 汇编失败 @0x%x 指令 '%s': %s%n", p.address, p.instruction, ke.getMessage()); }
            }
            fos.write(buffer); System.out.printf("成功应用 %d 个 Patch 到 %s%n", appliedCount, outputFile.getName());
        } catch (IOException e) { System.err.println("应用 Patch 到文件时出错: " + e.getMessage()); e.printStackTrace(); }
        finally { if (keystone != null) keystone.close(); }
    }

    // --- 内部数据结构 ---
    static class InstructionContext { /* ... 不变 ... */
        final long relativeAddr; final Instruction instruction; final List<Number> registers;
        InstructionContext(long addr, Instruction ins, List<Number> regs) { this.relativeAddr = addr; this.instruction = ins; this.registers = regs; }
    }
    static class CselInfo { /* ... 不变 ... */
        final long cselAddress; final String destinationRegister; final String condition; final String trueSourceReg; final String falseSourceReg; final long trueSourceValue; final long falseSourceValue;
        CselInfo(long addr, String destReg, String cond, String trueReg, String falseReg, long tVal, long fVal) { this.cselAddress = addr; this.destinationRegister = destReg; this.condition = cond; this.trueSourceReg = trueReg; this.falseSourceReg = falseReg; this.trueSourceValue = tVal; this.falseSourceValue = fVal; }
    }
    static class Patch { /* ... 不变 ... */
        final long address; final String instruction; final long targetAddress;
        Patch(long addr, String ins, long target) { this.address = addr; this.instruction = ins; this.targetAddress = target; }
    }
    // --- 新增：模拟任务的数据结构 ---
    static class SimulationTask {
        final CselInfo cselInfo;
        final long brRelativeAddr;
        final List<Number> registersBeforeCsel; // CSEL 执行前的寄存器状态
        final long cselAbsoluteAddr;
        final long brAbsoluteAddr;

        SimulationTask(CselInfo cselInfo, long brRelativeAddr, List<Number> registersBeforeCsel, long cselAbsAddr, long brAbsAddr) {
            this.cselInfo = cselInfo;
            this.brRelativeAddr = brRelativeAddr;
            this.registersBeforeCsel = registersBeforeCsel; // 存储状态
            this.cselAbsoluteAddr = cselAbsAddr;
            this.brAbsoluteAddr = brAbsAddr;
        }
    }

    // --- 主执行逻辑 ---
    public static void main(String[] args) {
        System.out.println("启动 DeOllvmBr (双模拟器方法)...");
        DeOllvmBr_TwoEmus deobf = null;

        try {
            // 1. 初始化 (会创建两个模拟器并加载 SO)
            deobf = new DeOllvmBr_TwoEmus();

            // 2. 执行主模拟器代码以收集任务
            System.out.println("\n[阶段 1] 执行主模拟器以查找 CSEL-BR 模式并收集任务...");
            // ==================================================================
            // !!! 重要: 修改这里来调用包含混淆代码的函数 !!!
            System.out.println("警告: 正在调用 JNI_OnLoad 作为示例，可能无法触发目标 Hook 代码。请修改！");
            deobf.dm.callJNI_OnLoad(deobf.emulator);
            // 例如: deobf.module.callFunction(deobf.emulator, 0xYourFunctionOffset);
            // ==================================================================
            System.out.println("[阶段 1] 主模拟器执行完成。收集到 " + deobf.simulationTasks.size() + " 个模拟任务。");


            // 3. 使用临时模拟器处理收集到的任务
            System.out.println("\n[阶段 2] 使用临时模拟器处理任务并生成 Patch...");
            if (!deobf.simulationTasks.isEmpty()) {
                for (SimulationTask task : deobf.simulationTasks) {
                    deobf.performSimulationsOnTmpEmu(task);
                }
                System.out.println("[阶段 2] 所有模拟任务处理完毕。");
            } else {
                System.out.println("[阶段 2] 没有需要模拟的任务。");
            }

            // 4. 应用生成的 Patch
            System.out.println("\n[阶段 3] 应用生成的 Patch 到文件...");
            deobf.applyPatches();

        } catch (Exception e) {
            System.err.println("在执行或 Patch 过程中发生错误:");
            e.printStackTrace();
        } finally {
            // 5. 清理资源 (关闭两个模拟器)
            if (deobf != null) {
                System.out.println("\n[清理] 关闭模拟器...");
                try {
                    if (deobf.emulator != null) deobf.emulator.close();
                    System.out.println("  主模拟器已关闭。");
                } catch (IOException e) { System.err.println("关闭主模拟器时出错: " + e.getMessage()); }
                try {
                    if (deobf.tmpEmulator != null) deobf.tmpEmulator.close();
                    System.out.println("  临时模拟器已关闭。");
                } catch (IOException e) { System.err.println("关闭临时模拟器时出错: " + e.getMessage()); }

                if (deobf.capstone != null) deobf.capstone.close();
                // Keystone 在 applyPatches 中关闭
            }
        }
        System.out.println("\nDeOllvmBr 执行完毕。");
    }
}
```



#### 执行前后对比

![image-20250707115957916](https://cdn.jsdelivr.net/gh/Aar0n3906/blog-img/image-20250707115957916.png)
