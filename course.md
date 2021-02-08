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
