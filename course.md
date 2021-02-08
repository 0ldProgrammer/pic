- Fonctionnement basique
    - Registre
      - Registre 32-bits
      - Registre 64-bits
    - ASLR
      - Où est stocker le fichier ASLR pour l'activer ou le désactiver ?
    - Explication de l'exploitation de retour à la libc
      - Faille ret2libc

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

Le buffer overflow est une vulnérabilité présente lorsque le programmeur ne vérifie pas la taille d’une variable fournie par l’utilisateur, et qu’il stocke cette variable en mémoire. Il est alors possible pour l’attaquant d’entrer une valeur de taille supérieure à ce qui était prévu, et lorsque cette valeur (appelée buffer) est copiée en mémoire, elle dépasse de l’espace qui lui était alloué (dépassement de tampon).

Donc, basiquement la technique de la retour à la libc s'applique lorsque la pile n'est pas exécutable, le but est d'utiliser les fonctions de la `libc` comme `system()`, `exit()` pour essayer de faire exécuter une commande au programme alors que le programme n'était pas prévu pour cela.

