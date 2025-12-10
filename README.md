# TP NOTÉ - REVERSE ENGINEERING
# Analyse des applications appXX

Date : 10 décembre 2025

---

## TABLE DES MATIÈRES

1. [Application 01 - Affichage de températures](#application-01)
2. [Application 02 - Vérification de clé simple](#application-02)
3. [Application 03 - Vérification de clé avec fonction](#application-03)
4. [Application 04 - Authentification multi-facteurs](#application-04)
5. [Application 05 - Vérification de clé avec échantillonnage](#application-05)
6. [Application 06 - Vérification de clé avec XOR](#application-06)
7. [Application 07 - Vérification de clé avec double XOR](#application-07)

---

## MÉTHODOLOGIE GÉNÉRALE

Pour chaque application, j'ai suivi ces étapes :

1. Identifier le type de fichier
2. Extraire les chaînes de caractères
3. Désassembler le binaire
4. Analyser le code assembleur
5. Tester les mots de passe trouvés

---

## APPLICATION 01

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app01
```

**Sortie obtenue :**
```
app01: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, not stripped
```

**Explication :**
- **ELF 32-bit** : Fichier exécutable Linux 32 bits
- **Intel i386** : Architecture x86 (processeur 32 bits)
- **dynamically linked** : Utilise des bibliothèques partagées
- **not stripped** : Les symboles de débogage sont présents (facilite l'analyse)

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app01
```

**Sortie obtenue (extrait) :**
```
Il fait %02i degré
```

**Explication :**
- Cette chaîne contient un format `%02i` qui sera remplacé par un nombre
- Le programme affiche probablement des températures

### Étape 3 : Désassemblage

**Commande exécutée :**
```bash
objdump -d app01 > app01.asm
```

**Explication :**
- `objdump` : Outil pour analyser les fichiers binaires
- `-d` : Désassemble le code machine en assembleur
- `> app01.asm` : Redirige la sortie vers un fichier

### Étape 4 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app01 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049000 <_init>:
08049020 <__libc_start_main@plt-0x10>:
08049030 <__libc_start_main@plt>:
08049040 <printf@plt>:
08049050 <_start>:
08049080 <_dl_relocate_static_pie>:
08049090 <__x86.get_pc_thunk.bx>:
080490a0 <deregister_tm_clones>:
080490e0 <register_tm_clones>:
08049120 <__do_global_dtors_aux>:
08049150 <frame_dummy>:
08049156 <main>:
08049198 <_fini>:
```

**Explication :**
Le binaire contient 13 fonctions au total :
- **Fonctions système d'initialisation** : `_init`, `_start`, `_dl_relocate_static_pie`
- **Fonctions PLT (Procedure Linkage Table)** : `__libc_start_main@plt`, `printf@plt`
- **Fonctions de gestion de la mémoire** : `deregister_tm_clones`, `register_tm_clones`, `__do_global_dtors_aux`
- **Fonction helper** : `__x86.get_pc_thunk.bx`, `frame_dummy`
- **Fonction principale** : `main`
- **Fonction de finalisation** : `_fini`

### Étape 4.1 : Analyse détaillée de toutes les fonctions

#### Fonction 1 : _init (adresse 0x08049000)

**Code assembleur complet :**
```asm
08049000 <_init>:
 8049000:	53                   	push   %ebx
 8049001:	83 ec 08             	sub    $0x8,%esp
 8049004:	e8 87 00 00 00       	call   8049090 <__x86.get_pc_thunk.bx>
 8049009:	81 c3 eb 2f 00 00    	add    $0x2feb,%ebx
 804900f:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 8049015:	85 c0                	test   %eax,%eax
 8049017:	74 02                	je     804901b <_init+0x1b>
 8049019:	ff d0                	call   *%eax
 804901b:	83 c4 08             	add    $0x8,%esp
 804901e:	5b                   	pop    %ebx
 804901f:	c3                   	ret
```

**Prologue (lignes 8049000-8049001) :**
- `push %ebx` : Sauvegarde le registre EBX sur la pile
- `sub $0x8,%esp` : Alloue 8 octets sur la pile pour les variables locales

**Corps de la fonction (lignes 8049004-8049019) :**
- `call 8049090` : Appel à `__x86.get_pc_thunk.bx` pour obtenir l'adresse de base
- `add $0x2feb,%ebx` : Ajuste EBX avec l'offset de la GOT (Global Offset Table)
- `mov -0x4(%ebx),%eax` : Charge un pointeur de fonction depuis la GOT
- `test %eax,%eax` : Vérifie si le pointeur est NULL
- `je 804901b` : Si NULL, saute à l'épilogue
- `call *%eax` : Sinon, appelle la fonction pointée (initialisation dynamique)

**Épilogue (lignes 804901b-804901f) :**
- `add $0x8,%esp` : Libère l'espace alloué sur la pile
- `pop %ebx` : Restaure EBX
- `ret` : Retourne à l'appelant

**Explication :**
Fonction d'initialisation exécutée avant `main()`. Elle initialise les constructeurs globaux et prépare l'environnement d'exécution.

---

#### Fonction 2 : _start (adresse 0x08049050)

**Code assembleur complet :**
```asm
08049050 <_start>:
 8049050:	31 ed                	xor    %ebp,%ebp
 8049052:	5e                   	pop    %esi
 8049053:	89 e1                	mov    %esp,%ecx
 8049055:	83 e4 f0             	and    $0xfffffff0,%esp
 8049058:	50                   	push   %eax
 8049059:	54                   	push   %esp
 804905a:	52                   	push   %edx
 804905b:	e8 19 00 00 00       	call   8049079 <_start+0x29>
 8049060:	81 c3 94 2f 00 00    	add    $0x2f94,%ebx
 8049066:	6a 00                	push   $0x0
 8049068:	6a 00                	push   $0x0
 804906a:	51                   	push   %ecx
 804906b:	56                   	push   %esi
 804906c:	c7 c0 56 91 04 08    	mov    $0x8049156,%eax
 8049072:	50                   	push   %eax
 8049073:	e8 b8 ff ff ff       	call   8049030 <__libc_start_main@plt>
 8049078:	f4                   	hlt
```

**Prologue (lignes 8049050-804905a) :**
- `xor %ebp,%ebp` : Met EBP à zéro (marque le début de la pile pour le débogueur)
- `pop %esi` : Récupère argc (nombre d'arguments) dans ESI
- `mov %esp,%ecx` : Sauvegarde le pointeur sur argv dans ECX
- `and $0xfffffff0,%esp` : Aligne la pile sur 16 octets
- `push %eax`, `push %esp`, `push %edx` : Empile des arguments pour `__libc_start_main`

**Corps de la fonction (lignes 804905b-8049073) :**
- `call 8049079` : Appelle une sous-routine inline (pour obtenir PC)
- `add $0x2f94,%ebx` : Ajuste EBX pour position-independent code
- `push $0x0` : fini (pointeur vers _fini)
- `push $0x0` : init (pointeur vers _init)
- `push %ecx` : argv
- `push %esi` : argc
- `mov $0x8049156,%eax` : Charge l'adresse de main dans EAX
- `push %eax` : main
- `call __libc_start_main@plt` : Appelle la fonction de démarrage de la libc

**Épilogue (ligne 8049078) :**
- `hlt` : Arrête le processeur (ne devrait jamais être atteint)

**Explication :**
Point d'entrée du programme. Configure l'environnement et appelle `__libc_start_main` qui appellera ensuite `main()`.

---

#### Fonction 3 : __x86.get_pc_thunk.bx (adresse 0x08049090)

**Code assembleur complet :**
```asm
08049090 <__x86.get_pc_thunk.bx>:
 8049090:	8b 1c 24             	mov    (%esp),%ebx
 8049093:	c3                   	ret
```

**Prologue :** Aucun (fonction leaf)

**Corps de la fonction (ligne 8049090) :**
- `mov (%esp),%ebx` : Copie l'adresse de retour (haut de la pile) dans EBX

**Épilogue (ligne 8049093) :**
- `ret` : Retourne à l'appelant

**Explication :**
Fonction helper pour le code position-independent (PIC). Permet d'obtenir le Program Counter (PC) actuel dans EBX en récupérant l'adresse de retour sur la pile.

---

#### Fonction 4 : _dl_relocate_static_pie (adresse 0x08049080)

**Code assembleur complet :**
```asm
08049080 <_dl_relocate_static_pie>:
 8049080:	c3                   	ret
```

**Prologue :** Aucun

**Corps de la fonction :** Vide (fonction stub)

**Épilogue (ligne 8049080) :**
- `ret` : Retourne immédiatement

**Explication :**
Stub pour la relocation PIE (Position Independent Executable) statique. Fonction vide car le binaire ne nécessite pas de relocation statique.

---

#### Fonction 5 : deregister_tm_clones (adresse 0x080490a0)

**Code assembleur complet :**
```asm
080490a0 <deregister_tm_clones>:
 80490a0:	b8 10 c0 04 08       	mov    $0x804c010,%eax
 80490a5:	3d 10 c0 04 08       	cmp    $0x804c010,%eax
 80490aa:	74 24                	je     80490d0 <deregister_tm_clones+0x30>
 80490ac:	b8 00 00 00 00       	mov    $0x0,%eax
 80490b1:	85 c0                	test   %eax,%eax
 80490b3:	74 1b                	je     80490d0 <deregister_tm_clones+0x30>
 80490b5:	55                   	push   %ebp
 80490b6:	89 e5                	mov    %esp,%ebp
 80490b8:	83 ec 14             	sub    $0x14,%esp
 80490bb:	68 10 c0 04 08       	push   $0x804c010
 80490c0:	ff d0                	call   *%eax
 80490c2:	83 c4 10             	add    $0x10,%esp
 80490c5:	c9                   	leave
 80490c6:	c3                   	ret
 80490d0:	c3                   	ret
```

**Prologue conditionnel (lignes 80490b5-80490b8) :**
- `push %ebp` : Sauvegarde EBP
- `mov %esp,%ebp` : Établit le nouveau frame pointer
- `sub $0x14,%esp` : Alloue 20 octets sur la pile

**Corps de la fonction (lignes 80490a0-80490c0) :**
- `mov $0x804c010,%eax` : Charge l'adresse du segment __TMC_END__
- `cmp $0x804c010,%eax` : Compare avec la même adresse
- `je 80490d0` : Si égales, saute à la fin (pas de clones à désenregistrer)
- `mov $0x0,%eax` : Charge un pointeur de fonction (NULL dans ce cas)
- `test %eax,%eax` : Vérifie si le pointeur est NULL
- `je 80490d0` : Si NULL, saute à la fin
- `push $0x804c010` : Empile l'argument
- `call *%eax` : Appelle la fonction de désenregistrement

**Épilogue (lignes 80490c2-80490c6 ou 80490d0) :**
- `add $0x10,%esp` : Nettoie les arguments (si appelé)
- `leave` : Restaure ESP et EBP
- `ret` : Retourne

**Explication :**
Désenregistre les "clones" de fonctions utilisés pour le transactional memory. Dans ce binaire simple, la fonction ne fait rien.

---

#### Fonction 6 : register_tm_clones (adresse 0x080490e0)

**Code assembleur complet :**
```asm
080490e0 <register_tm_clones>:
 80490e0:	b8 10 c0 04 08       	mov    $0x804c010,%eax
 80490e5:	2d 10 c0 04 08       	sub    $0x804c010,%eax
 80490ea:	89 c2                	mov    %eax,%edx
 80490ec:	c1 e8 1f             	shr    $0x1f,%eax
 80490ef:	c1 fa 02             	sar    $0x2,%edx
 80490f2:	01 d0                	add    %edx,%eax
 80490f4:	d1 f8                	sar    $1,%eax
 80490f6:	74 20                	je     8049118 <register_tm_clones+0x38>
 80490f8:	ba 00 00 00 00       	mov    $0x0,%edx
 80490fd:	85 d2                	test   %edx,%edx
 80490ff:	74 17                	je     8049118 <register_tm_clones+0x38>
 8049101:	55                   	push   %ebp
 8049102:	89 e5                	mov    %esp,%ebp
 8049104:	83 ec 10             	sub    $0x10,%esp
 8049107:	50                   	push   %eax
 8049108:	68 10 c0 04 08       	push   $0x804c010
 804910d:	ff d2                	call   *%edx
 804910f:	83 c4 10             	add    $0x10,%esp
 8049112:	c9                   	leave
 8049113:	c3                   	ret
 8049118:	c3                   	ret
```

**Prologue conditionnel (lignes 8049101-8049104) :**
- `push %ebp` : Sauvegarde EBP
- `mov %esp,%ebp` : Établit le frame pointer
- `sub $0x10,%esp` : Alloue 16 octets

**Corps de la fonction (lignes 80490e0-804910d) :**
- `mov $0x804c010,%eax` : Charge l'adresse __TMC_END__
- `sub $0x804c010,%eax` : Calcule la taille (résultat = 0)
- `mov %eax,%edx` : Copie dans EDX
- `shr $0x1f,%eax` : Décale de 31 bits (obtient le bit de signe)
- `sar $0x2,%edx` : Divise par 4 (arithmetic shift)
- `add %edx,%eax` : Ajoute les deux
- `sar $1,%eax` : Divise par 2
- `je 8049118` : Si résultat nul, saute à la fin
- `mov $0x0,%edx` : Charge le pointeur de fonction (NULL)
- `test %edx,%edx` : Teste si NULL
- `je 8049118` : Si NULL, saute à la fin
- `push %eax`, `push $0x804c010` : Empile les arguments
- `call *%edx` : Appelle la fonction

**Épilogue (lignes 804910f-8049113 ou 8049118) :**
- `add $0x10,%esp` : Nettoie les arguments
- `leave` : Restaure le frame
- `ret` : Retourne

**Explication :**
Enregistre les clones de fonctions pour le transactional memory. Comme `deregister_tm_clones`, cette fonction ne fait rien dans ce binaire simple.

---

#### Fonction 7 : __do_global_dtors_aux (adresse 0x08049120)

**Code assembleur complet :**
```asm
08049120 <__do_global_dtors_aux>:
 8049120:	f3 0f 1e fb          	endbr32
 8049124:	80 3d 10 c0 04 08 00 	cmpb   $0x0,0x804c010
 804912b:	75 1b                	jne    8049148 <__do_global_dtors_aux+0x28>
 804912d:	55                   	push   %ebp
 804912e:	89 e5                	mov    %esp,%ebp
 8049130:	83 ec 08             	sub    $0x8,%esp
 8049133:	e8 68 ff ff ff       	call   80490a0 <deregister_tm_clones>
 8049138:	c6 05 10 c0 04 08 01 	movb   $0x1,0x804c010
 804913f:	c9                   	leave
 8049140:	c3                   	ret
 8049148:	c3                   	ret
```

**Prologue (lignes 8049120 et 804912d-8049130) :**
- `endbr32` : Instruction de sécurité Control-flow Enforcement Technology (CET)
- `push %ebp` : Sauvegarde EBP
- `mov %esp,%ebp` : Établit le frame pointer
- `sub $0x8,%esp` : Alloue 8 octets

**Corps de la fonction (lignes 8049124-8049138) :**
- `cmpb $0x0,0x804c010` : Vérifie un flag global (déjà exécuté ?)
- `jne 8049148` : Si déjà exécuté, saute à la fin
- `call 80490a0` : Appelle `deregister_tm_clones`
- `movb $0x1,0x804c010` : Marque la fonction comme exécutée

**Épilogue (lignes 804913f-8049140 ou 8049148) :**
- `leave` : Restaure le frame
- `ret` : Retourne

**Explication :**
Exécute les destructeurs globaux (global destructors). Appelée automatiquement à la sortie du programme pour nettoyer les objets globaux C++. Le flag empêche une double exécution.

---

#### Fonction 8 : frame_dummy (adresse 0x08049150)

**Code assembleur complet :**
```asm
08049150 <frame_dummy>:
 8049150:	f3 0f 1e fb          	endbr32
 8049154:	eb 8a                	jmp    80490e0 <register_tm_clones>
```

**Prologue :** Aucun

**Corps de la fonction (lignes 8049150-8049154) :**
- `endbr32` : Instruction CET
- `jmp 80490e0` : Saute directement à `register_tm_clones`

**Épilogue :** Aucun (tail call)

**Explication :**
Fonction wrapper qui appelle simplement `register_tm_clones`. Utilisée pour initialiser les frames de débogage.

---

#### Fonction 9 : main (adresse 0x08049156) - **FONCTION PRINCIPALE**

**Code assembleur complet :**
```asm
08049156 <main>:
 8049156:	55                   	push   %ebp
 8049157:	89 e5                	mov    %esp,%ebp
 8049159:	83 ec 0c             	sub    $0xc,%esp
 804915c:	c7 45 f8 0a 00 00 00 	movl   $0xa,-0x8(%ebp)
 8049163:	c7 45 fc 63 00 00 00 	movl   $0x63,-0x4(%ebp)
 804916a:	8b 45 f8             	mov    -0x8(%ebp),%eax
 804916d:	89 45 f4             	mov    %eax,-0xc(%ebp)
 8049170:	eb 14                	jmp    8049186 <main+0x30>
 8049172:	ff 75 f4             	push   -0xc(%ebp)
 8049175:	68 08 a0 04 08       	push   $0x804a008
 804917a:	e8 c1 fe ff ff       	call   8049040 <printf@plt>
 804917f:	83 c4 08             	add    $0x8,%esp
 8049182:	83 45 f4 01          	addl   $0x1,-0xc(%ebp)
 8049186:	8b 45 f4             	mov    -0xc(%ebp),%eax
 8049189:	3b 45 fc             	cmp    -0x4(%ebp),%eax
 804918c:	7c e4                	jl     8049172 <main+0x1c>
 804918e:	b8 00 00 00 00       	mov    $0x0,%eax
 8049193:	c9                   	leave
 8049194:	c3                   	ret
```

**Prologue (lignes 8049156-8049159) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer
- `mov %esp,%ebp` : Établit le nouveau frame pointer
- `sub $0xc,%esp` : Alloue 12 octets pour les variables locales (3 int)

**Corps de la fonction (lignes 804915c-804918c) :**
- `movl $0xa,-0x8(%ebp)` : Stocke 10 (0x0a) dans la variable locale à EBP-8 (debut)
- `movl $0x63,-0x4(%ebp)` : Stocke 99 (0x63) dans la variable locale à EBP-4 (fin)
- `mov -0x8(%ebp),%eax` : Charge debut dans EAX
- `mov %eax,-0xc(%ebp)` : Initialise le compteur i à EBP-12 avec debut
- `jmp 8049186` : Saute à la condition de la boucle

**Boucle (lignes 8049172-804918c) :**
- `push -0xc(%ebp)` : Empile i (l'argument pour printf)
- `push $0x804a008` : Empile l'adresse de la chaîne "Il fait %02i degré"
- `call printf@plt` : Appelle printf
- `add $0x8,%esp` : Nettoie les arguments (2 x 4 octets)
- `addl $0x1,-0xc(%ebp)` : i++ (incrémente le compteur)
- `mov -0xc(%ebp),%eax` : Charge i dans EAX
- `cmp -0x4(%ebp),%eax` : Compare i avec fin (99)
- `jl 8049172` : Si i < 99, retourne au début de la boucle

**Épilogue (lignes 804918e-8049194) :**
- `mov $0x0,%eax` : Met 0 dans EAX (valeur de retour)
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp` (restaure le frame)
- `ret` : Retourne au caller

**Explication :**
Fonction principale du programme. Implémente une boucle for qui affiche les températures de 10 à 98 degrés.

---

#### Fonction 10 : _fini (adresse 0x08049198)

**Code assembleur complet :**
```asm
08049198 <_fini>:
 8049198:	53                   	push   %ebx
 8049199:	83 ec 08             	sub    $0x8,%esp
 804919c:	e8 ef fe ff ff       	call   8049090 <__x86.get_pc_thunk.bx>
 80491a1:	81 c3 53 2e 00 00    	add    $0x2e53,%ebx
 80491a7:	83 c4 08             	add    $0x8,%esp
 80491aa:	5b                   	pop    %ebx
 80491ab:	c3                   	ret
```

**Prologue (lignes 8049198-8049199) :**
- `push %ebx` : Sauvegarde EBX
- `sub $0x8,%esp` : Alloue 8 octets

**Corps de la fonction (lignes 804919c-80491a1) :**
- `call 8049090` : Appelle `__x86.get_pc_thunk.bx`
- `add $0x2e53,%ebx` : Ajuste EBX pour PIC

**Épilogue (lignes 80491a7-80491ab) :**
- `add $0x8,%esp` : Libère l'espace alloué
- `pop %ebx` : Restaure EBX
- `ret` : Retourne

**Explication :**
Fonction de finalisation exécutée après `main()`. Nettoie les ressources et appelle les destructeurs finaux.

---

### Pseudo-code

```c
// Programme qui affiche des températures de 10 à 98 degrés
int main() {
    int i;

    for (i = 10; i < 99; i++) {
        printf("Il fait %02i degré", i);
    }

    return 0;
}
```

### Test du programme

**Commande exécutée :**
```bash
./app01
```

**Sortie obtenue (extrait) :**
```
Il fait 10 degré
Il fait 11 degré
Il fait 12 degré
...
Il fait 98 degré
```

**Résultat :** ✅ Pas de mot de passe, simple affichage

---

## APPLICATION 02

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app02
```

**Sortie obtenue :**
```
app02: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

**Explication :** Même type de fichier que app01

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app02
```

**Sortie obtenue (extrait) :**
```
Key?
dOxgFpCDHhoa3
Good!
Bad :(
```

**Explication :**
- **Key?** : Le programme demande un mot de passe
- **dOxgFpCDHhoa3** : Mot de passe stocké en clair dans le binaire
- **Good!** / **Bad :(** : Messages de réussite/échec

### Étape 3 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app02 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049000 <_init>:
08049020 <__libc_start_main@plt-0x10>:
08049030 <__libc_start_main@plt>:
08049040 <printf@plt>:
08049050 <fgets@plt>:
08049060 <__stack_chk_fail@plt>:
08049070 <puts@plt>:
08049080 <strncmp@plt>:
08049090 <_start>:
080490c0 <_dl_relocate_static_pie>:
080490d0 <__x86.get_pc_thunk.bx>:
080490e0 <deregister_tm_clones>:
08049120 <register_tm_clones>:
08049160 <__do_global_dtors_aux>:
08049190 <frame_dummy>:
08049196 <main>:
08049214 <_fini>:
```

**Explication :**
Le binaire contient 16 fonctions au total. Par rapport à app01, app02 ajoute 4 fonctions PLT supplémentaires :
- **fgets@plt** : Pour lire l'entrée utilisateur de manière sécurisée
- **__stack_chk_fail@plt** : Pour la protection contre les buffer overflows (stack canary)
- **puts@plt** : Pour afficher les messages Good!/Bad
- **strncmp@plt** : Pour comparer le mot de passe entré avec le mot de passe attendu

### Étape 3.1 : Analyse détaillée des fonctions spécifiques à app02

#### Fonction principale : main (adresse 0x08049196)

**Code assembleur complet :**
```asm
08049196 <main>:
 8049196:	55                   	push   %ebp
 8049197:	89 e5                	mov    %esp,%ebp
 8049199:	83 ec 24             	sub    $0x24,%esp
 804919c:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 80491a2:	89 45 fc             	mov    %eax,-0x4(%ebp)
 80491a5:	31 c0                	xor    %eax,%eax
 80491a7:	68 08 a0 04 08       	push   $0x804a008
 80491ac:	e8 8f fe ff ff       	call   8049040 <printf@plt>
 80491b1:	83 c4 04             	add    $0x4,%esp
 80491b4:	a1 20 c0 04 08       	mov    0x804c020,%eax
 80491b9:	50                   	push   %eax
 80491ba:	6a 1f                	push   $0x1f
 80491bc:	8d 45 dc             	lea    -0x24(%ebp),%eax
 80491bf:	50                   	push   %eax
 80491c0:	e8 8b fe ff ff       	call   8049050 <fgets@plt>
 80491c5:	83 c4 0c             	add    $0xc,%esp
 80491c8:	6a 0d                	push   $0xd
 80491ca:	68 0e a0 04 08       	push   $0x804a00e
 80491cf:	8d 45 dc             	lea    -0x24(%ebp),%eax
 80491d2:	50                   	push   %eax
 80491d3:	e8 a8 fe ff ff       	call   8049080 <strncmp@plt>
 80491d8:	83 c4 0c             	add    $0xc,%esp
 80491db:	85 c0                	test   %eax,%eax
 80491dd:	75 0f                	jne    80491ee <main+0x58>
 80491df:	68 1c a0 04 08       	push   $0x804a01c
 80491e4:	e8 87 fe ff ff       	call   8049070 <puts@plt>
 80491e9:	83 c4 04             	add    $0x4,%esp
 80491ec:	eb 0d                	jmp    80491fb <main+0x65>
 80491ee:	68 23 a0 04 08       	push   $0x804a023
 80491f3:	e8 78 fe ff ff       	call   8049070 <puts@plt>
 80491f8:	83 c4 04             	add    $0x4,%esp
 80491fb:	b8 00 00 00 00       	mov    $0x0,%eax
 8049200:	8b 55 fc             	mov    -0x4(%ebp),%edx
 8049203:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 804920a:	74 05                	je     8049211 <main+0x7b>
 804920c:	e8 4f fe ff ff       	call   8049060 <__stack_chk_fail@plt>
 8049211:	c9                   	leave
 8049212:	c3                   	ret
```

**Prologue (lignes 8049196-80491a5) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer
- `mov %esp,%ebp` : Établit le nouveau frame pointer
- `sub $0x24,%esp` : Alloue 36 octets (0x24) pour les variables locales
- `mov %gs:0x14,%eax` : Lit le **stack canary** depuis le segment GS (protection stack)
- `mov %eax,-0x4(%ebp)` : Stocke le canary à EBP-4
- `xor %eax,%eax` : Met EAX à zéro (nettoie le canary d'EAX pour la sécurité)

**Corps de la fonction - Affichage du prompt (lignes 80491a7-80491b1) :**
- `push $0x804a008` : Empile l'adresse de "Key? "
- `call printf@plt` : Affiche "Key? "
- `add $0x4,%esp` : Nettoie l'argument (4 octets)

**Corps de la fonction - Lecture de l'entrée (lignes 80491b4-80491c5) :**
- `mov 0x804c020,%eax` : Charge stdin (flux d'entrée standard)
- `push %eax` : Empile stdin comme 3ème argument de fgets
- `push $0x1f` : Empile 31 (0x1f) comme 2ème argument (taille max)
- `lea -0x24(%ebp),%eax` : Calcule l'adresse du buffer (EBP-0x24)
- `push %eax` : Empile l'adresse du buffer comme 1er argument
- `call fgets@plt` : Lit l'entrée utilisateur (max 31 caractères)
- `add $0xc,%esp` : Nettoie les 3 arguments (3 x 4 = 12 octets)

**Corps de la fonction - Comparaison (lignes 80491c8-80491db) :**
- `push $0xd` : Empile 13 (0x0d) comme 3ème argument (longueur à comparer)
- `push $0x804a00e` : Empile l'adresse de "dOxgFpCDHhoa3" (mot de passe attendu)
- `lea -0x24(%ebp),%eax` : Calcule l'adresse du buffer d'entrée
- `push %eax` : Empile l'adresse du buffer comme 1er argument
- `call strncmp@plt` : Compare les 13 premiers caractères
- `add $0xc,%esp` : Nettoie les 3 arguments
- `test %eax,%eax` : Teste le résultat (0 = égal, non-0 = différent)
- `jne 80491ee` : Si différent, saute au message "Bad"

**Corps de la fonction - Affichage du résultat (lignes 80491df-80491f8) :**
- **Si égal (lignes 80491df-80491ec) :**
  - `push $0x804a01c` : Empile l'adresse de "Good!"
  - `call puts@plt` : Affiche "Good!"
  - `add $0x4,%esp` : Nettoie l'argument
  - `jmp 80491fb` : Saute à la fin
- **Si différent (lignes 80491ee-80491f8) :**
  - `push $0x804a023` : Empile l'adresse de "Bad :("
  - `call puts@plt` : Affiche "Bad :("
  - `add $0x4,%esp` : Nettoie l'argument

**Épilogue (lignes 80491fb-8049212) :**
- `mov $0x0,%eax` : Met 0 dans EAX (valeur de retour)
- `mov -0x4(%ebp),%edx` : Récupère le stack canary stocké
- `sub %gs:0x14,%edx` : Soustrait le canary original
- `je 8049211` : Si égaux (résultat = 0), le stack n'a pas été corrompu, continue
- `call __stack_chk_fail@plt` : **Sinon, détection de buffer overflow ! Appelle la fonction d'erreur**
- `leave` : Restaure le frame
- `ret` : Retourne

**Explication détaillée du stack canary :**
Le **stack canary** est une technique de sécurité contre les buffer overflows :
1. Au début de la fonction, une valeur aléatoire (canary) est lue depuis `%gs:0x14`
2. Cette valeur est stockée sur la pile juste avant l'adresse de retour
3. Avant de retourner, le programme vérifie si le canary a changé
4. Si un buffer overflow a écrasé le stack, le canary sera corrompu
5. La fonction `__stack_chk_fail` est appelée pour terminer le programme proprement

**Explication détaillée de strncmp :**
`strncmp(s1, s2, n)` compare les n premiers caractères de deux chaînes :
- Retourne 0 si s1 == s2 (sur n caractères)
- Retourne < 0 si s1 < s2
- Retourne > 0 si s1 > s2

Ici, `strncmp(input, "dOxgFpCDHhoa3", 13)` compare les 13 premiers caractères.

**Note sur les autres fonctions :**
Les fonctions `_init`, `_start`, `__x86.get_pc_thunk.bx`, `deregister_tm_clones`, `register_tm_clones`, `__do_global_dtors_aux`, `frame_dummy`, et `_fini` sont identiques à app01 (fonctions standard de l'environnement d'exécution C). Seule la fonction `main` diffère.

---

### Pseudo-code

```c
// Programme qui vérifie un mot de passe
int main() {
    char input[50];

    printf("Key? ");
    scanf("%s", input);

    if (input == "dOxgFpCDHhoa3") {
        printf("Good!\n");
    } else {
        printf("Bad :(\n");
    }

    return 0;
}
```

### Test du mot de passe

**Commande exécutée :**
```bash
echo "dOxgFpCDHhoa3" | ./app02
```

**Sortie obtenue :**
```
Key? Good!
```

**Résultat :** ✅ Mot de passe trouvé : `dOxgFpCDHhoa3`

---

## APPLICATION 03

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app03
```

**Sortie obtenue :**
```
app03: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app03
```

**Sortie obtenue (extrait) :**
```
Key?
Good!
Bad :(
```

**Explication :**
- Pas de mot de passe visible directement dans les chaînes
- Le mot de passe doit être caché dans le code

### Étape 3 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app03 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049000 <_init>:
08049020 <__libc_start_main@plt-0x10>:
08049030 <__libc_start_main@plt>:
08049040 <printf@plt>:
08049050 <fgets@plt>:
08049060 <__stack_chk_fail@plt>:
08049070 <puts@plt>:
08049080 <strncmp@plt>:
08049090 <_start>:
080490c0 <_dl_relocate_static_pie>:
080490d0 <__x86.get_pc_thunk.bx>:
080490e0 <deregister_tm_clones>:
08049120 <register_tm_clones>:
08049160 <__do_global_dtors_aux>:
08049190 <frame_dummy>:
08049196 <check_password>:
080491fa <main>:
08049278 <_fini>:
```

**Explication :**
App03 introduit une **fonction personnalisée** : `check_password`. C'est la première application qui sépare la logique de vérification du mot de passe dans une fonction dédiée, démontr ant une meilleure architecture logicielle.

### Étape 3.1 : Analyse détaillée des fonctions spécifiques à app03

#### Fonction 1 : check_password (adresse 0x08049196) - **FONCTION PERSONNALISÉE**

**Code assembleur complet :**
```asm
08049196 <check_password>:
 8049196:	55                   	push   %ebp
 8049197:	89 e5                	mov    %esp,%ebp
 8049199:	83 ec 18             	sub    $0x18,%esp
 804919c:	8b 45 08             	mov    0x8(%ebp),%eax
 804919f:	89 45 e8             	mov    %eax,-0x18(%ebp)
 80491a2:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 80491a8:	89 45 fc             	mov    %eax,-0x4(%ebp)
 80491ab:	31 c0                	xor    %eax,%eax
 80491ad:	c7 45 ef 2b 4c 52 72 	movl   $0x72524c2b,-0x11(%ebp)
 80491b4:	c7 45 f3 4e 32 7a 54 	movl   $0x547a324e,-0xd(%ebp)
 80491bb:	c7 45 f7 31 53 45 47 	movl   $0x47455331,-0x9(%ebp)
 80491c2:	c6 45 fb 00          	movb   $0x0,-0x5(%ebp)
 80491c6:	6a 0c                	push   $0xc
 80491c8:	8d 45 ef             	lea    -0x11(%ebp),%eax
 80491cb:	50                   	push   %eax
 80491cc:	ff 75 e8             	push   -0x18(%ebp)
 80491cf:	e8 ac fe ff ff       	call   8049080 <strncmp@plt>
 80491d4:	83 c4 0c             	add    $0xc,%esp
 80491d7:	85 c0                	test   %eax,%eax
 80491d9:	75 07                	jne    80491e2 <check_password+0x4c>
 80491db:	b8 01 00 00 00       	mov    $0x1,%eax
 80491e0:	eb 05                	jmp    80491e7 <check_password+0x51>
 80491e2:	b8 00 00 00 00       	mov    $0x0,%eax
 80491e7:	8b 55 fc             	mov    -0x4(%ebp),%edx
 80491ea:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 80491f1:	74 05                	je     80491f8 <check_password+0x62>
 80491f3:	e8 68 fe ff ff       	call   8049060 <__stack_chk_fail@plt>
 80491f8:	c9                   	leave
 80491f9:	c3                   	ret
```

**Prologue (lignes 8049196-80491ab) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer
- `mov %esp,%ebp` : Établit le nouveau frame pointer
- `sub $0x18,%esp` : Alloue 24 octets (0x18) pour les variables locales
- `mov 0x8(%ebp),%eax` : Récupère le 1er paramètre (pointeur vers l'entrée utilisateur) depuis la pile
- `mov %eax,-0x18(%ebp)` : Stocke ce pointeur dans une variable locale (EBP-0x18)
- `mov %gs:0x14,%eax` : Lit le stack canary
- `mov %eax,-0x4(%ebp)` : Stocke le canary à EBP-4
- `xor %eax,%eax` : Nettoie EAX

**Corps de la fonction - Construction du mot de passe en mémoire (lignes 80491ad-80491c2) :**
- `movl $0x72524c2b,-0x11(%ebp)` : Stocke 0x72524c2b à EBP-0x11
  - En little-endian : `2b 4c 52 72` → `+`, `L`, `R`, `r`
- `movl $0x547a324e,-0xd(%ebp)` : Stocke 0x547a324e à EBP-0x0d
  - En little-endian : `4e 32 7a 54` → `N`, `2`, `z`, `T`
- `movl $0x47455331,-0x9(%ebp)` : Stocke 0x47455331 à EBP-0x09
  - En little-endian : `31 53 45 47` → `1`, `S`, `E`, `G`
- `movb $0x0,-0x5(%ebp)` : Ajoute le terminateur nul '\0' à EBP-0x05

**Note importante sur l'adressage :**
Le mot de passe est construit entre EBP-0x11 et EBP-0x05 :
```
EBP-0x11: '+'  = 0x2b
EBP-0x10: 'L'  = 0x4c
EBP-0x0f: 'R'  = 0x52
EBP-0x0e: 'r'  = 0x72
EBP-0x0d: 'N'  = 0x4e
EBP-0x0c: '2'  = 0x32
EBP-0x0b: 'z'  = 0x7a
EBP-0x0a: 'T'  = 0x54
EBP-0x09: '1'  = 0x31
EBP-0x08: 'S'  = 0x53
EBP-0x07: 'E'  = 0x45
EBP-0x06: 'G'  = 0x47
EBP-0x05: '\0' = 0x00
```
Mot de passe : **+LRrN2zT1SEG**

**Corps de la fonction - Comparaison (lignes 80491c6-80491e2) :**
- `push $0xc` : Empile 12 (0x0c) - nombre de caractères à comparer
- `lea -0x11(%ebp),%eax` : Calcule l'adresse du mot de passe construit (EBP-0x11)
- `push %eax` : Empile cette adresse (2ème paramètre de strncmp)
- `push -0x18(%ebp)` : Empile le pointeur vers l'entrée utilisateur (1er paramètre)
- `call strncmp@plt` : Compare les 12 premiers caractères
- `add $0xc,%esp` : Nettoie les 3 arguments
- `test %eax,%eax` : Teste le résultat
- `jne 80491e2` : Si différent, saute pour retourner 0 (échec)
- `mov $0x1,%eax` : Met 1 dans EAX (succès)
- `jmp 80491e7` : Saute à l'épilogue
- **Cas d'échec (ligne 80491e2) :**
  - `mov $0x0,%eax` : Met 0 dans EAX (échec)

**Épilogue (lignes 80491e7-80491f9) :**
- `mov -0x4(%ebp),%edx` : Récupère le stack canary
- `sub %gs:0x14,%edx` : Compare avec le canary original
- `je 80491f8` : Si égal, tout va bien
- `call __stack_chk_fail@plt` : Sinon, détection de corruption
- `leave` : Restaure le frame
- `ret` : Retourne (avec 0 ou 1 dans EAX)

**Explication :**
Cette fonction construit dynamiquement le mot de passe sur la pile en utilisant des valeurs immédiates. C'est une technique d'obfuscation basique : le mot de passe n'apparaît pas en clair dans la section `.rodata` du binaire, rendant les outils comme `strings` inefficaces.

---

#### Fonction 2 : main (adresse 0x080491fa)

**Code assembleur complet :**
```asm
080491fa <main>:
 80491fa:	55                   	push   %ebp
 80491fb:	89 e5                	mov    %esp,%ebp
 80491fd:	83 ec 28             	sub    $0x28,%esp
 8049200:	8b 45 0c             	mov    0xc(%ebp),%eax
 8049203:	89 45 d8             	mov    %eax,-0x28(%ebp)
 8049206:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 804920c:	89 45 fc             	mov    %eax,-0x4(%ebp)
 804920f:	31 c0                	xor    %eax,%eax
 8049211:	68 08 a0 04 08       	push   $0x804a008
 8049216:	e8 25 fe ff ff       	call   8049040 <printf@plt>
 804921b:	83 c4 04             	add    $0x4,%esp
 804921e:	a1 20 c0 04 08       	mov    0x804c020,%eax
 8049223:	50                   	push   %eax
 8049224:	6a 1f                	push   $0x1f
 8049226:	8d 45 dc             	lea    -0x24(%ebp),%eax
 8049229:	50                   	push   %eax
 804922a:	e8 21 fe ff ff       	call   8049050 <fgets@plt>
 804922f:	83 c4 0c             	add    $0xc,%esp
 8049232:	8d 45 dc             	lea    -0x24(%ebp),%eax
 8049235:	50                   	push   %eax
 8049236:	e8 5b ff ff ff       	call   8049196 <check_password>
 804923b:	83 c4 04             	add    $0x4,%esp
 804923e:	85 c0                	test   %eax,%eax
 8049240:	74 0f                	je     8049251 <main+0x57>
 8049242:	68 0e a0 04 08       	push   $0x804a00e
 8049247:	e8 24 fe ff ff       	call   8049070 <puts@plt>
 804924c:	83 c4 04             	add    $0x4,%esp
 804924f:	eb 0d                	jmp    804925e <main+0x64>
 8049251:	68 15 a0 04 08       	push   $0x804a015
 8049256:	e8 15 fe ff ff       	call   8049070 <puts@plt>
 804925b:	83 c4 04             	add    $0x4,%esp
 804925e:	b8 00 00 00 00       	mov    $0x0,%eax
 8049263:	8b 55 fc             	mov    -0x4(%ebp),%edx
 8049266:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 804926d:	74 05                	je     8049274 <main+0x7a>
 804926f:	e8 ec fd ff ff       	call   8049060 <__stack_chk_fail@plt>
 8049274:	c9                   	leave
 8049275:	c3                   	ret
```

**Prologue (lignes 80491fa-804920f) :**
- `push %ebp` : Sauvegarde EBP
- `mov %esp,%ebp` : Établit le frame pointer
- `sub $0x28,%esp` : Alloue 40 octets (0x28)
- `mov 0xc(%ebp),%eax` : Récupère argv (paramètre de main)
- `mov %eax,-0x28(%ebp)` : Stocke argv (non utilisé ici)
- `mov %gs:0x14,%eax` : Lit le stack canary
- `mov %eax,-0x4(%ebp)` : Stocke le canary
- `xor %eax,%eax` : Nettoie EAX

**Corps de la fonction - Affichage et lecture (lignes 8049211-804922f) :**
- `push $0x804a008` : Empile "Key? "
- `call printf@plt` : Affiche le prompt
- `add $0x4,%esp` : Nettoie
- `mov 0x804c020,%eax` : Charge stdin
- `push %eax` : stdin
- `push $0x1f` : 31 (taille max)
- `lea -0x24(%ebp),%eax` : Adresse du buffer
- `push %eax` : buffer
- `call fgets@plt` : Lit l'entrée
- `add $0xc,%esp` : Nettoie

**Corps de la fonction - Appel de check_password (lignes 8049232-804923e) :**
- `lea -0x24(%ebp),%eax` : Calcule l'adresse du buffer d'entrée
- `push %eax` : Empile comme argument pour check_password
- `call 8049196 <check_password>` : **Appel de la fonction personnalisée**
- `add $0x4,%esp` : Nettoie l'argument
- `test %eax,%eax` : Teste la valeur de retour (1=succès, 0=échec)
- `je 8049251` : Si 0 (échec), saute au message Bad

**Corps de la fonction - Affichage du résultat (lignes 8049242-804925b) :**
- **Succès (lignes 8049242-804924f) :**
  - `push $0x804a00e` : "Good!"
  - `call puts@plt` : Affiche
  - `jmp 804925e` : Saute à la fin
- **Échec (lignes 8049251-804925b) :**
  - `push $0x804a015` : "Bad :("
  - `call puts@plt` : Affiche

**Épilogue (lignes 804925e-8049275) :**
- `mov $0x0,%eax` : Valeur de retour = 0
- `mov -0x4(%ebp),%edx` : Récupère le canary
- `sub %gs:0x14,%edx` : Vérifie
- `je 8049274` : Si OK, continue
- `call __stack_chk_fail@plt` : Sinon, erreur
- `leave` : Restaure
- `ret` : Retourne

**Explication :**
La fonction main est maintenant plus propre : elle délègue la vérification du mot de passe à `check_password`. C'est un exemple de **séparation des responsabilités** (separation of concerns), un principe fondamental en programmation.

**Note sur les autres fonctions :**
Les fonctions système (_init, _start, etc.) sont identiques à app02.

---

### Pseudo-code

```c
// Programme avec mot de passe construit en mémoire
int main() {
    char input[50];
    char password[] = "+LRrN2zT1SEG";  // Construit dans la mémoire

    printf("Key? ");
    scanf("%s", input);

    if (input == password) {
        printf("Good!\n");
    } else {
        printf("Bad :(\n");
    }

    return 0;
}
```

### Test du mot de passe

**Commande exécutée :**
```bash
echo "+LRrN2zT1SEG" | ./app03
```

**Sortie obtenue :**
```
Key? Good!
```

**Résultat :** ✅ Mot de passe trouvé : `+LRrN2zT1SEG`

---

## APPLICATION 04

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app04
```

**Sortie obtenue :**
```
app04: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app04
```

**Sortie obtenue (extrait) :**
```
ajacobe
BPYWHwivoYmi
816201
User?
Key?
TOTP?
Good!
Bad username :(
Bad password :(
Bad TOTP :(
```

**Explication :**
- Le programme demande **3 informations** : User, Key et TOTP
- Les 3 valeurs attendues sont visibles : `ajacobe`, `BPYWHwivoYmi`, `816201`

### Étape 3 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app04 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049000 <_init>:
08049020 <__libc_start_main@plt-0x10>:
08049030 <__libc_start_main@plt>:
08049040 <printf@plt>:
08049050 <fgets@plt>:
08049060 <__stack_chk_fail@plt>:
08049070 <puts@plt>:
08049080 <strncmp@plt>:
08049090 <_start>:
080490c0 <_dl_relocate_static_pie>:
080490d0 <__x86.get_pc_thunk.bx>:
080490e0 <deregister_tm_clones>:
08049120 <register_tm_clones>:
08049160 <__do_global_dtors_aux>:
08049190 <frame_dummy>:
08049196 <check_username>:
080491bd <check_password>:
080491e4 <check_totp>:
0804920b <main>:
08049308 <_fini>:
```

**Explication :**
App04 implémente une **authentification multi-facteurs (MFA)** avec 3 fonctions de vérification séparées :
- `check_username` : Vérifie le nom d'utilisateur
- `check_password` : Vérifie le mot de passe
- `check_totp` : Vérifie le code TOTP (Time-based One-Time Password)

Cette architecture modulaire permet une meilleure séparation des préoccupations et facilite la maintenance.

### Étape 3.1 : Analyse détaillée des fonctions spécifiques à app04

#### Fonction 1 : check_username (adresse 0x08049196)

**Code assembleur complet :**
```asm
08049196 <check_username>:
 8049196:	55                   	push   %ebp
 8049197:	89 e5                	mov    %esp,%ebp
 8049199:	6a 07                	push   $0x7
 804919b:	ff 75 08             	push   0x8(%ebp)
 804919e:	68 08 a0 04 08       	push   $0x804a008
 80491a3:	e8 d8 fe ff ff       	call   8049080 <strncmp@plt>
 80491a8:	83 c4 0c             	add    $0xc,%esp
 80491ab:	85 c0                	test   %eax,%eax
 80491ad:	75 07                	jne    80491b6 <check_username+0x20>
 80491af:	b8 01 00 00 00       	mov    $0x1,%eax
 80491b4:	eb 05                	jmp    80491bb <check_username+0x25>
 80491b6:	b8 00 00 00 00       	mov    $0x0,%eax
 80491bb:	c9                   	leave
 80491bc:	c3                   	ret
```

**Prologue (lignes 8049196-8049197) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
  - Note : Pas d'allocation de pile (`sub $x,%esp`) car pas de variables locales
  - Pas de stack canary car la fonction est simple sans buffer

**Corps de la fonction (lignes 8049199-80491b6) :**
- `push $0x7` : Empile 7 (0x07) comme 3ème argument de strncmp (nombre d'octets à comparer)
- `push 0x8(%ebp)` : Empile le pointeur vers l'entrée utilisateur (1er paramètre de check_username, à EBP+8)
- `push $0x804a008` : Empile l'adresse 0x804a008 (où se trouve "ajacobe") comme 2ème argument
- `call strncmp@plt` : Appelle strncmp(input, "ajacobe", 7) via la PLT
- `add $0xc,%esp` : Nettoie les 3 arguments de la pile (3 × 4 = 12 = 0x0c octets)
- `test %eax,%eax` : Teste le résultat de strncmp (EAX AND EAX, modifie les flags)
  - strncmp retourne 0 si égal, non-0 si différent
- `jne 80491b6` : Si non égal (ZF=0), saute à l'adresse 80491b6 (retourne 0)
- `mov $0x1,%eax` : Met 1 dans EAX (succès - les chaînes sont égales)
- `jmp 80491bb` : Saute inconditionnellement à l'épilogue
- **Bloc d'échec (ligne 80491b6) :**
  - `mov $0x0,%eax` : Met 0 dans EAX (échec - les chaînes sont différentes)

**Épilogue (lignes 80491bb-80491bc) :**
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure ESP à sa valeur avant l'appel
  - Restaure l'ancien EBP depuis la pile
- `ret` : Retourne à l'appelant (avec 0 ou 1 dans EAX)

**Explication :**
Fonction simple qui compare le username avec "ajacobe" (7 caractères). Pas de stack canary car pas de buffer local ni d'opérations sensibles sur la pile.

---

#### Fonction 2 : check_password (adresse 0x080491bd)

**Code assembleur complet :**
```asm
080491bd <check_password>:
 80491bd:	55                   	push   %ebp
 80491be:	89 e5                	mov    %esp,%ebp
 80491c0:	6a 0c                	push   $0xc
 80491c2:	ff 75 08             	push   0x8(%ebp)
 80491c5:	68 10 a0 04 08       	push   $0x804a010
 80491ca:	e8 b1 fe ff ff       	call   8049080 <strncmp@plt>
 80491cf:	83 c4 0c             	add    $0xc,%esp
 80491d2:	85 c0                	test   %eax,%eax
 80491d4:	75 07                	jne    80491dd <check_password+0x20>
 80491d6:	b8 01 00 00 00       	mov    $0x1,%eax
 80491db:	eb 05                	jmp    80491e2 <check_password+0x25>
 80491dd:	b8 00 00 00 00       	mov    $0x0,%eax
 80491e2:	c9                   	leave
 80491e3:	c3                   	ret
```

**Prologue (lignes 80491bd-80491be) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
  - Même structure que check_username : pas d'allocation locale ni de canary

**Corps de la fonction (lignes 80491c0-80491dd) :**
- `push $0xc` : Empile 12 (0x0c) comme 3ème argument (12 caractères à comparer)
- `push 0x8(%ebp)` : Empile le pointeur vers l'entrée utilisateur (paramètre à EBP+8)
- `push $0x804a010` : Empile l'adresse 0x804a010 (où se trouve "BPYWHwivoYmi")
- `call strncmp@plt` : Appelle strncmp(input, "BPYWHwivoYmi", 12)
- `add $0xc,%esp` : Nettoie les 3 arguments (12 octets)
- `test %eax,%eax` : Teste le résultat de strncmp
- `jne 80491dd` : Si différent (ZF=0), saute au bloc d'échec
- `mov $0x1,%eax` : Met 1 dans EAX (succès)
- `jmp 80491e2` : Saute à l'épilogue
- **Bloc d'échec (ligne 80491dd) :**
  - `mov $0x0,%eax` : Met 0 dans EAX (échec)

**Épilogue (lignes 80491e2-80491e3) :**
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure ESP et récupère l'ancien EBP
- `ret` : Retourne à l'appelant (valeur de retour dans EAX)

**Explication :**
Même structure que check_username, mais compare 12 caractères avec "BPYWHwivoYmi". Les trois fonctions de vérification (username, password, totp) partagent la même architecture simple sans variables locales.

---

#### Fonction 3 : check_totp (adresse 0x080491e4)

**Code assembleur complet :**
```asm
080491e4 <check_totp>:
 80491e4:	55                   	push   %ebp
 80491e5:	89 e5                	mov    %esp,%ebp
 80491e7:	6a 06                	push   $0x6
 80491e9:	ff 75 08             	push   0x8(%ebp)
 80491ec:	68 1d a0 04 08       	push   $0x804a01d
 80491f1:	e8 8a fe ff ff       	call   8049080 <strncmp@plt>
 80491f6:	83 c4 0c             	add    $0xc,%esp
 80491f9:	85 c0                	test   %eax,%eax
 80491fb:	75 07                	jne    8049204 <check_totp+0x20>
 80491fd:	b8 01 00 00 00       	mov    $0x1,%eax
 8049202:	eb 05                	jmp    8049209 <check_totp+0x25>
 8049204:	b8 00 00 00 00       	mov    $0x0,%eax
 8049209:	c9                   	leave
 804920a:	c3                   	ret
```

**Prologue (lignes 80491e4-80491e5) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
  - Même architecture simple que les deux fonctions précédentes

**Corps de la fonction (lignes 80491e7-8049204) :**
- `push $0x6` : Empile 6 comme 3ème argument (6 caractères à comparer)
- `push 0x8(%ebp)` : Empile le pointeur vers l'entrée utilisateur (paramètre à EBP+8)
- `push $0x804a01d` : Empile l'adresse 0x804a01d (où se trouve "816201")
- `call strncmp@plt` : Appelle strncmp(input, "816201", 6)
- `add $0xc,%esp` : Nettoie les 3 arguments de la pile (12 octets)
- `test %eax,%eax` : Teste le résultat de strncmp
- `jne 8049204` : Si différent (ZF=0), saute au bloc d'échec
- `mov $0x1,%eax` : Met 1 dans EAX (succès - code TOTP valide)
- `jmp 8049209` : Saute à l'épilogue
- **Bloc d'échec (ligne 8049204) :**
  - `mov $0x0,%eax` : Met 0 dans EAX (échec - code TOTP invalide)

**Épilogue (lignes 8049209-804920a) :**
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure le stack frame
- `ret` : Retourne à l'appelant (0 ou 1 dans EAX)

**Explication :**
Vérifie le code TOTP (6 chiffres). TOTP = Time-based One-Time Password, un code temporaire souvent utilisé pour l'authentification à deux facteurs (2FA). Cette fonction a la même structure que check_username et check_password, seule la longueur de comparaison diffère (6 au lieu de 7 ou 12).

---

#### Fonction 4 : main (adresse 0x0804920b)

**Code assembleur (extraits clés - fonction longue) :**
```asm
0804920b <main>:
 # Prologue
 804920b:	55                   	push   %ebp
 804920c:	89 e5                	mov    %esp,%ebp
 804920e:	83 ec 50             	sub    $0x50,%esp
 8049211:	8b 45 0c             	mov    0xc(%ebp),%eax
 8049214:	89 45 b0             	mov    %eax,-0x50(%ebp)
 8049217:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 804921d:	89 45 fc             	mov    %eax,-0x4(%ebp)
 8049220:	31 c0                	xor    %eax,%eax

 # Lecture username
 8049222:	68 24 a0 04 08       	push   $0x804a024
 8049227:	e8 14 fe ff ff       	call   8049040 <printf@plt>
 804922c:	83 c4 04             	add    $0x4,%esp
 804922f:	a1 20 c0 04 08       	mov    0x804c020,%eax
 8049234:	50                   	push   %eax
 8049235:	6a 1f                	push   $0x1f
 8049237:	8d 45 bc             	lea    -0x44(%ebp),%eax
 804923a:	50                   	push   %eax
 804923b:	e8 10 fe ff ff       	call   8049050 <fgets@plt>
 8049240:	83 c4 0c             	add    $0xc,%esp

 # Lecture password
 8049243:	68 2b a0 04 08       	push   $0x804a02b
 8049248:	e8 f3 fd ff ff       	call   8049040 <printf@plt>
 804924d:	83 c4 04             	add    $0x4,%esp
 8049250:	a1 20 c0 04 08       	mov    0x804c020,%eax
 8049255:	50                   	push   %eax
 8049256:	6a 1f                	push   $0x1f
 8049258:	8d 45 dc             	lea    -0x24(%ebp),%eax
 804925b:	50                   	push   %eax
 804925c:	e8 ef fd ff ff       	call   8049050 <fgets@plt>
 8049261:	83 c4 0c             	add    $0xc,%esp

 # Lecture TOTP
 8049264:	68 31 a0 04 08       	push   $0x804a031
 8049269:	e8 d2 fd ff ff       	call   8049040 <printf@plt>
 804926e:	83 c4 04             	add    $0x4,%esp
 8049271:	a1 20 c0 04 08       	mov    0x804c020,%eax
 8049276:	50                   	push   %eax
 8049277:	6a 07                	push   $0x7
 8049279:	8d 45 b4             	lea    -0x4c(%ebp),%eax
 804927c:	50                   	push   %eax
 804927d:	e8 ce fd ff ff       	call   8049050 <fgets@plt>
 8049282:	83 c4 0c             	add    $0xc,%esp

 # Vérification en cascade
 8049285:	8d 45 bc             	lea    -0x44(%ebp),%eax
 8049288:	50                   	push   %eax
 8049289:	e8 08 ff ff ff       	call   8049196 <check_username>
 804928e:	83 c4 04             	add    $0x4,%esp
 8049291:	85 c0                	test   %eax,%eax
 8049293:	74 4d                	je     80492e2 <main+0xd7>  # Bad username
 8049295:	8d 45 dc             	lea    -0x24(%ebp),%eax
 8049298:	50                   	push   %eax
 8049299:	e8 1f ff ff ff       	call   80491bd <check_password>
 804929e:	83 c4 04             	add    $0x4,%esp
 80492a1:	85 c0                	test   %eax,%eax
 80492a3:	74 2e                	je     80492d3 <main+0xc8>  # Bad password
 80492a5:	8d 45 b4             	lea    -0x4c(%ebp),%eax
 80492a8:	50                   	push   %eax
 80492a9:	e8 36 ff ff ff       	call   80491e4 <check_totp>
 80492ae:	83 c4 04             	add    $0x4,%esp
 80492b1:	85 c0                	test   %eax,%eax
 80492b3:	74 0f                	je     80492c4 <main+0xb9>  # Bad TOTP
 80492b5:	68 38 a0 04 08       	push   $0x804a038  # "Good!"
 80492ba:	e8 b1 fd ff ff       	call   8049070 <puts@plt>
 80492bf:	83 c4 04             	add    $0x4,%esp
 80492c2:	eb 2b                	jmp    80492ef <main+0xe4>

 # Messages d'erreur
 80492c4:	68 3f a0 04 08       	push   $0x804a03f  # "Bad TOTP :("
 80492c9:	e8 a2 fd ff ff       	call   8049070 <puts@plt>
 80492ce:	83 c4 04             	add    $0x4,%esp
 80492d1:	eb 1c                	jmp    80492ef <main+0xe4>
 80492d3:	68 4c a0 04 08       	push   $0x804a04c  # "Bad password :("
 80492d8:	e8 93 fd ff ff       	call   8049070 <puts@plt>
 80492dd:	83 c4 04             	add    $0x4,%esp
 80492e0:	eb 0d                	jmp    80492ef <main+0xe4>
 80492e2:	68 5d a0 04 08       	push   $0x804a05d  # "Bad username :("
 80492e7:	e8 84 fd ff ff       	call   8049070 <puts@plt>
 80492ec:	83 c4 04             	add    $0x4,%esp

 # Épilogue
 80492ef:	b8 00 00 00 00       	mov    $0x0,%eax
 80492f4:	8b 55 fc             	mov    -0x4(%ebp),%edx
 80492f7:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 80492fe:	74 05                	je     8049305 <main+0xfa>
 8049300:	e8 5b fd ff ff       	call   8049060 <__stack_chk_fail@plt>
 8049305:	c9                   	leave
 8049306:	c3                   	ret
```

**Prologue (lignes 804920b-8049220) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
- `sub $0x50,%esp` : Alloue 80 octets (0x50) sur la pile pour les variables locales
  - Grande allocation pour stocker trois buffers séparés pour les trois inputs
- `mov 0xc(%ebp),%eax` : Récupère argv (2ème paramètre de main) depuis EBP+0x0c
- `mov %eax,-0x50(%ebp)` : Sauvegarde argv à EBP-0x50
- `mov %gs:0x14,%eax` : Lit le stack canary depuis le Thread Local Storage (segment GS, offset 0x14)
- `mov %eax,-0x4(%ebp)` : Stocke le canary à EBP-0x4 (haut de la pile locale)
- `xor %eax,%eax` : Met EAX à zéro pour éviter les fuites du canary en mémoire

**Organisation de la pile locale :**
- EBP-0x04 : Stack canary (protection buffer overflow)
- EBP-0x24 : Buffer password (32 octets)
- EBP-0x44 : Buffer username (32 octets)
- EBP-0x4c : Buffer TOTP (8 octets)
- EBP-0x50 : Sauvegarde de argv

**Corps - Lecture des 3 entrées (lignes 8049222-8049282) :**
1. Affiche "User? " et lit dans le buffer à EBP-0x44
2. Affiche "Key? " et lit dans le buffer à EBP-0x24
3. Affiche "TOTP? " et lit dans le buffer à EBP-0x4c

**Corps - Vérification en cascade (lignes 8049285-80492c2) :**
1. Appelle `check_username` avec le 1er buffer
   - Si échec (EAX=0), saute à "Bad username :("
2. Si succès, appelle `check_password` avec le 2ème buffer
   - Si échec, saute à "Bad password :("
3. Si succès, appelle `check_totp` avec le 3ème buffer
   - Si échec, saute à "Bad TOTP :("
4. Si tout réussit, affiche "Good!"

**Corps - Gestion des erreurs (lignes 80492c4-80492ec) :**
Trois blocs distincts pour afficher les messages d'erreur appropriés.

**Épilogue (lignes 80492ef-8049306) :**
- `mov $0x0,%eax` : Met 0 dans EAX (valeur de retour de main)
- `mov -0x4(%ebp),%edx` : Récupère le stack canary sauvegardé à EBP-0x4
- `sub %gs:0x14,%edx` : Soustrait le canary original du TLS
  - Si la pile n'a pas été corrompue, EDX devrait maintenant contenir 0
- `je 8049305` : Si égal (ZF=1, EDX=0), saute à l'instruction leave (pile intacte)
- `call __stack_chk_fail@plt` : Sinon, appelle __stack_chk_fail pour terminer le programme
  - Cette fonction ne retourne jamais, elle appelle abort()
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure le stack frame avant de retourner
- `ret` : Retourne à l'appelant (retour au système d'exploitation)

**Explication :**
Architecture en **cascade** : chaque vérification doit réussir pour passer à la suivante. C'est une implémentation typique d'un système MFA (Multi-Factor Authentication). Si une vérification échoue, le programme affiche un message d'erreur spécifique indiquant quel facteur a échoué.

---

### Pseudo-code

```c
// Programme avec authentification à 3 facteurs
int main() {
    char username[50];
    char password[50];
    char totp[10];

    printf("User? ");
    scanf("%s", username);

    printf("Key? ");
    scanf("%s", password);

    printf("TOTP? ");
    scanf("%s", totp);

    if (username != "ajacobe") {
        printf("Bad username :(\n");
    } else if (password != "BPYWHwivoYmi") {
        printf("Bad password :(\n");
    } else if (totp != "816201") {
        printf("Bad TOTP :(\n");
    } else {
        printf("Good!\n");
    }

    return 0;
}
```

### Test des mots de passe

**Commande exécutée :**
```bash
(echo "ajacobe"; echo "BPYWHwivoYmi"; echo "816201") | ./app04
```

**Sortie obtenue :**
```
User? Key? TOTP? Good!
```

**Résultat :** ✅ Mots de passe trouvés :
- Username : `ajacobe`
- Password : `BPYWHwivoYmi`
- TOTP : `816201`

---

## APPLICATION 05

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app05
```

**Sortie obtenue :**
```
app05: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app05
```

**Sortie obtenue (extrait) :**
```
Password?
Good!
Bad :(
```

**Explication :**
- Pas de mot de passe visible
- Il faut analyser le code assembleur

### Étape 3 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app05 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049080 <_start>:
080490b0 <_dl_relocate_static_pie>:
080490c0 <__x86.get_pc_thunk.bx>:
080490d0 <deregister_tm_clones>:
08049110 <register_tm_clones>:
08049150 <__do_global_dtors_aux>:
08049180 <frame_dummy>:
08049186 <check_password>:
08049209 <main>:
08049288 <_fini>:
```

**Explication :**
App05 utilise une technique d'**échantillonnage** : seuls certains caractères du mot de passe sont vérifiés (positions paires uniquement).

### Étape 3.1 : Analyse détaillée de check_password (adresse 0x08049186)

**Code assembleur complet (extrait clé) :**
```asm
08049186 <check_password>:
 # Prologue
 8049186:	55                   	push   %ebp
 8049187:	89 e5                	mov    %esp,%ebp
 8049189:	83 ec 1c             	sub    $0x1c,%esp
 804918c:	8b 45 08             	mov    0x8(%ebp),%eax
 804918f:	89 45 e4             	mov    %eax,-0x1c(%ebp)
 8049192:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 8049198:	89 45 fc             	mov    %eax,-0x4(%ebp)
 804919b:	31 c0                	xor    %eax,%eax

 # Construction du mot de passe complet
 804919d:	c7 45 f0 74 6b 6a 65 	movl   $0x656a6b74,-0x10(%ebp)  # "tkje"
 80491a4:	c7 45 f4 46 36 78 47 	movl   $0x47783646,-0xc(%ebp)   # "F6xG"
 80491ab:	c7 45 f8 58 57 7a 2b 	movl   $0x2b7a5758,-0x8(%ebp)   # "XWz+"
 80491b2:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%ebp)        # i = 0
 80491b9:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)        # j = 0

 # Boucle de vérification
 80491c0:	eb 29                	jmp    80491eb <check_password+0x65>
 80491c2:	8b 55 e8             	mov    -0x18(%ebp),%edx        # edx = i
 80491c5:	8b 45 e4             	mov    -0x1c(%ebp),%eax        # eax = input
 80491c8:	01 d0                	add    %edx,%eax               # eax = &input[i]
 80491ca:	0f b6 10             	movzbl (%eax),%edx             # edx = input[i]
 80491cd:	8d 4d f0             	lea    -0x10(%ebp),%ecx        # ecx = password
 80491d0:	8b 45 ec             	mov    -0x14(%ebp),%eax        # eax = j
 80491d3:	01 c8                	add    %ecx,%eax               # eax = &password[j]
 80491d5:	0f b6 00             	movzbl (%eax),%eax             # eax = password[j]
 80491d8:	38 c2                	cmp    %al,%dl                 # compare input[i] == password[j]
 80491da:	74 07                	je     80491e3 <check_password+0x5d>
 80491dc:	b8 00 00 00 00       	mov    $0x0,%eax               # retourne 0
 80491e1:	eb 13                	jmp    80491f6 <check_password+0x70>
 80491e3:	83 45 e8 01          	addl   $0x1,-0x18(%ebp)        # i++
 80491e7:	83 45 ec 02          	addl   $0x2,-0x14(%ebp)        # j += 2 (ÉCHANTILLONNAGE!)
 80491eb:	83 7d ec 0b          	cmpl   $0xb,-0x14(%ebp)        # j <= 11 ?
 80491ef:	7e d1                	jle    80491c2 <check_password+0x3c>
 80491f1:	b8 01 00 00 00       	mov    $0x1,%eax               # retourne 1

 # Épilogue
 80491f6:	8b 55 fc             	mov    -0x4(%ebp),%edx
 80491f9:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 8049200:	74 05                	je     8049207 <check_password+0x81>
 8049202:	e8 59 fe ff ff       	call   8049060 <__stack_chk_fail@plt>
 8049207:	c9                   	leave
 8049208:	c3                   	ret
```

**Prologue (lignes 8049186-804919b) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
- `sub $0x1c,%esp` : Alloue 28 octets (0x1c) sur la pile pour les variables locales
  - Nécessaire pour stocker le mot de passe complet (12 octets) + compteurs + canary
- `mov 0x8(%ebp),%eax` : Récupère le paramètre input (pointeur vers la chaîne saisie)
- `mov %eax,-0x1c(%ebp)` : Sauvegarde le pointeur input à EBP-0x1c
- `mov %gs:0x14,%eax` : Lit le stack canary depuis le Thread Local Storage
- `mov %eax,-0x4(%ebp)` : Stocke le canary à EBP-0x4 (protection buffer overflow)
- `xor %eax,%eax` : Met EAX à zéro pour éviter les fuites du canary

**Corps - Construction du mot de passe :**
Le mot de passe complet "tkjeF6xGXWz+" (12 caractères) est construit sur la pile

**Corps - Boucle d'échantillonnage :**
```
Boucle: tant que j <= 11
  - Compare input[i] avec password[j]
  - Si différent, retourne 0
  - i++ (incrémente l'index d'entrée de 1)
  - j += 2 (incrémente l'index du mot de passe de 2) ← CLÉ!
```

**Résultat de l'échantillonnage :**
```
i=0: input[0] == password[0]  → 't'
i=1: input[1] == password[2]  → 'j'
i=2: input[2] == password[4]  → 'F'
i=3: input[3] == password[6]  → 'x'
i=4: input[4] == password[8]  → 'X'
i=5: input[5] == password[10] → 'z'
```
Mot de passe attendu : **tjFxXz** (6 caractères, positions paires uniquement)

**Épilogue (lignes 80491f6-8049208) :**
- `mov -0x4(%ebp),%edx` : Récupère le stack canary sauvegardé à EBP-0x4
- `sub %gs:0x14,%edx` : Soustrait le canary original du TLS
  - Si EDX = 0 après cette opération, la pile est intacte
- `je 8049207` : Si égal (ZF=1), saute à l'instruction leave (pas de corruption)
- `call __stack_chk_fail@plt` : Sinon, appelle __stack_chk_fail pour terminer
  - Protection contre buffer overflow détecté
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure le stack frame
- `ret` : Retourne à l'appelant (avec 0 ou 1 dans EAX)

**Explication :**
Technique d'obfuscation par échantillonnage : le programme stocke un mot de passe de 12 caractères mais n'en vérifie que 6 (1 sur 2). L'incrémentation `j += 2` est la clé de cette technique.

---

### Pseudo-code

```c
// Programme qui vérifie seulement certains caractères
int main() {
    char input[50];
    char password[] = "tkjeF6xGXWz+";  // Mot de passe complet

    printf("Password? ");
    scanf("%s", input);

    // Vérifie uniquement les positions paires (0, 2, 4, 6, 8, 10)
    if (input[0] == password[0] &&    // 't'
        input[1] == password[2] &&    // 'j'
        input[2] == password[4] &&    // 'F'
        input[3] == password[6] &&    // 'x'
        input[4] == password[8] &&    // 'X'
        input[5] == password[10]) {   // 'z'
        printf("Good!\n");
    } else {
        printf("Bad :(\n");
    }

    return 0;
}
```

### Test du mot de passe

**Commande exécutée :**
```bash
echo "tjFxXz" | ./app05
```

**Sortie obtenue :**
```
Password? Good!
```

**Résultat :** ✅ Mot de passe trouvé : `tjFxXz`

---

## APPLICATION 06

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app06
```

**Sortie obtenue :**
```
app06: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app06
```

**Sortie obtenue (extrait) :**
```
Password?
Good!
Bad :(
```

**Explication :**
- Pas de mot de passe visible
- Le mot de passe doit être chiffré

### Étape 3 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app06 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049080 <_start>:
080490b0 <_dl_relocate_static_pie>:
080490c0 <__x86.get_pc_thunk.bx>:
080490d0 <deregister_tm_clones>:
08049110 <register_tm_clones>:
08049150 <__do_global_dtors_aux>:
08049180 <frame_dummy>:
08049186 <check_password>:
08049201 <main>:
08049280 <_fini>:
```

**Explication :**
App06 utilise le **chiffrement XOR** avec une clé constante (0x21) pour obfusquer le mot de passe.

### Étape 3.1 : Analyse détaillée de check_password (adresse 0x08049186)

**Code assembleur complet (extrait clé) :**
```asm
08049186 <check_password>:
 # Prologue
 8049186:	55                   	push   %ebp
 8049187:	89 e5                	mov    %esp,%ebp
 8049189:	83 ec 18             	sub    $0x18,%esp
 804918c:	8b 45 08             	mov    0x8(%ebp),%eax
 804918f:	89 45 e8             	mov    %eax,-0x18(%ebp)
 8049192:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 8049198:	89 45 fc             	mov    %eax,-0x4(%ebp)
 804919b:	31 c0                	xor    %eax,%eax

 # Stockage du mot de passe chiffré
 804919d:	c7 45 f0 44 6d 58 69 	movl   $0x69586d44,-0x10(%ebp)  # Chiffré
 80491a4:	c7 45 f4 18 77 7b 49 	movl   $0x497b7718,-0xc(%ebp)   # Chiffré
 80491ab:	c7 45 f8 62 54 5b 51 	movl   $0x515b5462,-0x8(%ebp)   # Chiffré
 80491b2:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%ebp)        # i = 0

 # Boucle de vérification avec XOR
 80491b9:	eb 28                	jmp    80491e3 <check_password+0x5d>
 80491bb:	8b 55 ec             	mov    -0x14(%ebp),%edx        # edx = i
 80491be:	8b 45 e8             	mov    -0x18(%ebp),%eax        # eax = input
 80491c1:	01 d0                	add    %edx,%eax               # eax = &input[i]
 80491c3:	0f b6 00             	movzbl (%eax),%eax             # eax = input[i]
 80491c6:	8d 4d f0             	lea    -0x10(%ebp),%ecx        # ecx = encrypted
 80491c9:	8b 55 ec             	mov    -0x14(%ebp),%edx        # edx = i
 80491cc:	01 ca                	add    %ecx,%edx               # edx = &encrypted[i]
 80491ce:	0f b6 12             	movzbl (%edx),%edx             # edx = encrypted[i]
 80491d1:	83 f2 21             	xor    $0x21,%edx              # edx = encrypted[i] XOR 0x21 (DÉCHIFFREMENT!)
 80491d4:	38 d0                	cmp    %dl,%al                 # compare input[i] == decrypted[i]
 80491d6:	74 07                	je     80491df <check_password+0x59>
 80491d8:	b8 00 00 00 00       	mov    $0x0,%eax               # retourne 0
 80491dd:	eb 0f                	jmp    80491ee <check_password+0x68>
 80491df:	83 45 ec 01          	addl   $0x1,-0x14(%ebp)        # i++
 80491e3:	83 7d ec 0b          	cmpl   $0xb,-0x14(%ebp)        # i <= 11 ?
 80491e7:	7e d2                	jle    80491bb <check_password+0x35>
 80491e9:	b8 01 00 00 00       	mov    $0x1,%eax               # retourne 1

 # Épilogue
 80491ee:	8b 55 fc             	mov    -0x4(%ebp),%edx
 80491f1:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 80491f8:	74 05                	je     80491ff <check_password+0x79>
 80491fa:	e8 61 fe ff ff       	call   8049060 <__stack_chk_fail@plt>
 80491ff:	c9                   	leave
 8049200:	c3                   	ret
```

**Prologue (lignes 8049186-804919b) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
- `sub $0x18,%esp` : Alloue 24 octets (0x18) sur la pile
  - Espace pour le mot de passe chiffré (12 octets) + compteur + canary + pointeur input
- `mov 0x8(%ebp),%eax` : Récupère le paramètre input (pointeur vers la chaîne saisie)
- `mov %eax,-0x18(%ebp)` : Sauvegarde le pointeur input à EBP-0x18
- `mov %gs:0x14,%eax` : Lit le stack canary depuis le Thread Local Storage
- `mov %eax,-0x4(%ebp)` : Stocke le canary à EBP-0x4
- `xor %eax,%eax` : Met EAX à zéro pour éviter les fuites du canary

**Corps - Stockage du mot de passe chiffré :**
Le mot de passe est stocké sous forme chiffrée : `44 6d 58 69 18 77 7b 49 62 54 5b 51`

**Corps - Boucle de déchiffrement et comparaison :**
```
Pour chaque caractère i de 0 à 11 :
  1. Lire input[i]
  2. Lire encrypted[i]
  3. Déchiffrer : decrypted = encrypted[i] XOR 0x21
  4. Comparer input[i] avec decrypted
  5. Si différent, retourner 0
```

**Déchiffrement manuel :**
```
Octets chiffrés : 44 6d 58 69 18 77 7b 49 62 54 5b 51

0x44 XOR 0x21 = 0x65 = 'e'
0x6d XOR 0x21 = 0x4c = 'L'
0x58 XOR 0x21 = 0x79 = 'y'
0x69 XOR 0x21 = 0x48 = 'H'
0x18 XOR 0x21 = 0x39 = '9'
0x77 XOR 0x21 = 0x56 = 'V'
0x7b XOR 0x21 = 0x5a = 'Z'
0x49 XOR 0x21 = 0x68 = 'h'
0x62 XOR 0x21 = 0x43 = 'C'
0x54 XOR 0x21 = 0x75 = 'u'
0x5b XOR 0x21 = 0x7a = 'z'
0x51 XOR 0x21 = 0x70 = 'p'

Mot de passe : eLyH9VZhCuzp
```

**Épilogue (lignes 80491ee-8049200) :**
- `mov -0x4(%ebp),%edx` : Récupère le stack canary sauvegardé à EBP-0x4
- `sub %gs:0x14,%edx` : Soustrait le canary original du TLS
  - Si EDX = 0, la pile n'a pas été corrompue
- `je 80491ff` : Si égal (ZF=1), saute à l'instruction leave (pile intacte)
- `call __stack_chk_fail@plt` : Sinon, appelle __stack_chk_fail
  - Protection contre buffer overflow - termine le programme
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure le stack frame
- `ret` : Retourne à l'appelant (avec 0 ou 1 dans EAX)

**Explication :**
XOR (eXclusive OR) est une opération réversible : `A XOR K = B` et `B XOR K = A`. Ici, le mot de passe est stocké chiffré avec la clé 0x21, puis déchiffré à la volée lors de la comparaison. Cette technique empêche de trouver le mot de passe avec `strings` car il n'est jamais stocké en clair.

**Note sur XOR :**
XOR a la propriété : `X XOR K XOR K = X`. C'est pourquoi on peut chiffrer et déchiffrer avec la même clé.

---

### Pseudo-code

```c
// Programme avec mot de passe chiffré XOR
int main() {
    char input[50];
    char encrypted[] = {0x44, 0x6d, 0x58, 0x69, 0x18, 0x77,
                        0x7b, 0x49, 0x62, 0x54, 0x5b, 0x51};
    int key = 0x21;

    printf("Password? ");
    scanf("%s", input);

    // Déchiffre et compare chaque caractère
    int i;
    int ok = 1;
    for (i = 0; i < 12; i++) {
        char decrypted = encrypted[i] ^ key;  // XOR pour déchiffrer
        if (input[i] != decrypted) {
            ok = 0;
        }
    }

    if (ok) {
        printf("Good!\n");
    } else {
        printf("Bad :(\n");
    }

    return 0;
}
```

### Test du mot de passe

**Commande exécutée :**
```bash
echo "eLyH9VZhCuzp" | ./app06
```

**Sortie obtenue :**
```
Password? Good!
```

**Résultat :** ✅ Mot de passe trouvé : `eLyH9VZhCuzp`

---

## APPLICATION 07

### Étape 1 : Identification du fichier

**Commande exécutée :**
```bash
file app07
```

**Sortie obtenue :**
```
app07: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
```

### Étape 2 : Extraction des chaînes

**Commande exécutée :**
```bash
strings app07
```

**Sortie obtenue (extrait) :**
```
Password?
Good!
Bad :(
```

**Explication :**
- Pas de mot de passe visible
- Technique de chiffrement avancée

### Étape 3 : Analyse du code assembleur - Vue d'ensemble

**Commande pour lister toutes les fonctions :**
```bash
objdump -d app07 | grep "^[0-9a-f]\+ <"
```

**Sortie obtenue :**
```
08049080 <_start>:
080490b0 <_dl_relocate_static_pie>:
080490c0 <__x86.get_pc_thunk.bx>:
080490d0 <deregister_tm_clones>:
08049110 <register_tm_clones>:
08049150 <__do_global_dtors_aux>:
08049180 <frame_dummy>:
08049186 <check_password>:
08049216 <main>:
08049294 <_fini>:
```

**Explication :**
App07 utilise un **double XOR** : le mot de passe est obtenu en faisant XOR entre deux clés stockées séparément.

### Étape 3.1 : Analyse détaillée de check_password (adresse 0x08049186)

**Code assembleur complet (extrait clé) :**
```asm
08049186 <check_password>:
 # Prologue
 8049186:	55                   	push   %ebp
 8049187:	89 e5                	mov    %esp,%ebp
 8049189:	53                   	push   %ebx
 804918a:	83 ec 1c             	sub    $0x1c,%esp
 804918d:	8b 45 08             	mov    0x8(%ebp),%eax
 8049190:	89 45 e0             	mov    %eax,-0x20(%ebp)
 8049193:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 8049199:	89 45 f8             	mov    %eax,-0x8(%ebp)
 804919c:	31 c0                	xor    %eax,%eax

 # Stockage de la première clé
 804919e:	c7 45 e8 6e 0d 14 1e 	movl   $0x1e140d6e,-0x18(%ebp)  # Clé 1
 80491a5:	c7 45 ec 14 33 13 32 	movl   $0x32133314,-0x14(%ebp)  # Suite clé 1

 # Stockage de la deuxième clé
 80491ac:	c7 45 f0 17 65 22 50 	movl   $0x50226517,-0x10(%ebp)  # Clé 2
 80491b3:	c7 45 f4 75 42 69 01 	movl   $0x1694275,-0xc(%ebp)    # Suite clé 2

 # Initialisation compteur
 80491ba:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%ebp)        # i = 0

 # Boucle de vérification avec DOUBLE XOR
 80491c1:	eb 32                	jmp    80491f5 <check_password+0x6f>
 80491c3:	8b 55 e4             	mov    -0x1c(%ebp),%edx        # edx = i
 80491c6:	8b 45 e0             	mov    -0x20(%ebp),%eax        # eax = input
 80491c9:	01 d0                	add    %edx,%eax               # eax = &input[i]
 80491cb:	0f b6 00             	movzbl (%eax),%eax             # eax = input[i]
 80491ce:	8d 4d e8             	lea    -0x18(%ebp),%ecx        # ecx = key1
 80491d1:	8b 55 e4             	mov    -0x1c(%ebp),%edx        # edx = i
 80491d4:	01 ca                	add    %ecx,%edx               # edx = &key1[i]
 80491d6:	0f b6 1a             	movzbl (%edx),%ebx             # ebx = key1[i]
 80491d9:	8d 4d f0             	lea    -0x10(%ebp),%ecx        # ecx = key2
 80491dc:	8b 55 e4             	mov    -0x1c(%ebp),%edx        # edx = i
 80491df:	01 ca                	add    %ecx,%edx               # edx = &key2[i]
 80491e1:	0f b6 12             	movzbl (%edx),%edx             # edx = key2[i]
 80491e4:	31 da                	xor    %ebx,%edx               # edx = key1[i] XOR key2[i] (DOUBLE XOR!)
 80491e6:	38 d0                	cmp    %dl,%al                 # compare input[i] == (key1[i] XOR key2[i])
 80491e8:	74 07                	je     80491f1 <check_password+0x6b>
 80491ea:	b8 00 00 00 00       	mov    $0x0,%eax               # retourne 0
 80491ef:	eb 0f                	jmp    8049200 <check_password+0x7a>
 80491f1:	83 45 e4 01          	addl   $0x1,-0x1c(%ebp)        # i++
 80491f5:	83 7d e4 07          	cmpl   $0x7,-0x1c(%ebp)        # i <= 7 ?
 80491f9:	7e c8                	jle    80491c3 <check_password+0x3d>
 80491fb:	b8 01 00 00 00       	mov    $0x1,%eax               # retourne 1

 # Épilogue
 8049200:	8b 55 f8             	mov    -0x8(%ebp),%edx
 8049203:	65 2b 15 14 00 00 00 	sub    %gs:0x14,%edx
 804920a:	74 05                	je     8049211 <check_password+0x8b>
 804920c:	e8 4f fe ff ff       	call   8049060 <__stack_chk_fail@plt>
 8049211:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 8049214:	c9                   	leave
 8049215:	c3                   	ret
```

**Prologue (lignes 8049186-804919c) :**
- `push %ebp` : Sauvegarde l'ancien frame pointer sur la pile
- `mov %esp,%ebp` : Établit le nouveau frame pointer (EBP = ESP)
- `push %ebx` : Sauvegarde EBX car ce registre sera utilisé dans le corps de la fonction
  - Convention d'appel x86 : EBX est un registre préservé qui doit être sauvegardé
- `sub $0x1c,%esp` : Alloue 28 octets (0x1c) sur la pile
  - Espace pour les deux clés (16 octets) + compteur + canary + pointeur input
- `mov 0x8(%ebp),%eax` : Récupère le paramètre input (pointeur vers la chaîne saisie)
- `mov %eax,-0x20(%ebp)` : Sauvegarde le pointeur input à EBP-0x20
- `mov %gs:0x14,%eax` : Lit le stack canary depuis le Thread Local Storage
- `mov %eax,-0x8(%ebp)` : Stocke le canary à EBP-0x8
- `xor %eax,%eax` : Met EAX à zéro pour éviter les fuites du canary

**Corps - Stockage des deux clés :**
```
Clé 1 : 6e 0d 14 1e 14 33 13 32  (8 octets)
Clé 2 : 17 65 22 50 75 42 69 01  (8 octets)
```

**Corps - Boucle de vérification avec double XOR :**
```
Pour chaque caractère i de 0 à 7 :
  1. Lire input[i]
  2. Lire key1[i]
  3. Lire key2[i]
  4. Calculer : password[i] = key1[i] XOR key2[i]
  5. Comparer input[i] avec password[i]
  6. Si différent, retourner 0
```

**Calcul du mot de passe (double XOR) :**
```
i=0: 0x6e XOR 0x17 = 0x79 = 'y'
i=1: 0x0d XOR 0x65 = 0x68 = 'h'
i=2: 0x14 XOR 0x22 = 0x36 = '6'
i=3: 0x1e XOR 0x50 = 0x4e = 'N'
i=4: 0x14 XOR 0x75 = 0x61 = 'a'
i=5: 0x33 XOR 0x42 = 0x71 = 'q'
i=6: 0x13 XOR 0x69 = 0x7a = 'z'
i=7: 0x32 XOR 0x01 = 0x33 = '3'

Mot de passe : yh6Naqz3
```

**Épilogue (lignes 8049200-8049215) :**
- `mov -0x8(%ebp),%edx` : Récupère le stack canary sauvegardé à EBP-0x8
- `sub %gs:0x14,%edx` : Soustrait le canary original du TLS
  - Si EDX = 0 après soustraction, la pile est intacte
- `je 8049211` : Si égal (ZF=1), saute à l'instruction de restauration de EBX
- `call __stack_chk_fail@plt` : Sinon, appelle __stack_chk_fail
  - Protection contre buffer overflow - termine le programme
- `mov -0x4(%ebp),%ebx` : Restaure l'ancienne valeur de EBX depuis EBP-0x4
  - Nécessaire car EBX est un registre préservé (callee-saved)
- `leave` : Équivalent à `mov %ebp,%esp` puis `pop %ebp`
  - Restaure le stack frame et récupère l'ancien EBP
- `ret` : Retourne à l'appelant (avec 0 ou 1 dans EAX)

**Explication :**
Technique d'obfuscation avancée : le mot de passe n'est **jamais** stocké en mémoire, même chiffré ! Au lieu de cela, deux clés distinctes sont stockées, et le mot de passe est calculé à la volée par XOR entre ces deux clés. Cette technique rend l'analyse statique très difficile :
1. Le mot de passe ne peut pas être trouvé avec `strings`
2. Même en lisant la mémoire pendant l'exécution, on ne voit que les clés séparées
3. Il faut comprendre l'algorithme pour retrouver le mot de passe

**Schéma conceptuel :**
```
Clé 1:      [6e][0d][14][1e][14][33][13][32]
           XOR XOR XOR XOR XOR XOR XOR XOR
Clé 2:      [17][65][22][50][75][42][69][01]
           ===================================
Mot de passe: [y] [h] [6] [N] [a] [q] [z] [3]
```

---

### Pseudo-code

```c
// Programme avec double XOR
int main() {
    char input[50];
    char key1[] = {0x6e, 0x0d, 0x14, 0x1e, 0x14, 0x33, 0x13, 0x32};
    char key2[] = {0x17, 0x65, 0x22, 0x50, 0x75, 0x42, 0x69, 0x01};

    printf("Password? ");
    scanf("%s", input);

    // Compare avec le résultat de key1 XOR key2
    int i;
    int ok = 1;
    for (i = 0; i < 8; i++) {
        char expected = key1[i] ^ key2[i];  // Calcule le caractère attendu
        if (input[i] != expected) {
            ok = 0;
        }
    }

    if (ok) {
        printf("Good!\n");
    } else {
        printf("Bad :(\n");
    }

    return 0;
}
```

### Test du mot de passe

**Commande exécutée :**
```bash
echo "yh6Naqz3" | ./app07
```

**Sortie obtenue :**
```
Password? Good!
```

**Résultat :** ✅ Mot de passe trouvé : `yh6Naqz3`

---

## RÉSUMÉ DES MOTS DE PASSE TROUVÉS

| Application | Mot de passe | Technique utilisée |
|-------------|--------------|------------------------|
| app01 | N/A | Simple affichage (pas de mot de passe) |
| app02 | `dOxgFpCDHhoa3` | Stocké en clair dans le binaire |
| app03 | `+LRrN2zT1SEG` | Construit dynamiquement en mémoire |
| app04 | Username: `ajacobe`<br>Password: `BPYWHwivoYmi`<br>TOTP: `816201` | Authentification à 3 facteurs |
| app05 | `tjFxXz` | Vérification partielle (positions paires) |
| app06 | `eLyH9VZhCuzp` | Chiffrement XOR simple (clé 0x21) |
| app07 | `yh6Naqz3` | Double XOR (2 clés) |

---

## TECHNIQUES D'OBFUSCATION OBSERVÉES

### 1. Stockage en clair (app02)
Le mot de passe est directement visible avec la commande `strings`.
- **Difficulté** : ⭐☆☆☆☆ (Très facile)

### 2. Construction en mémoire (app03)
Le mot de passe est assemblé dans la pile à partir de valeurs hexadécimales.
- **Difficulté** : ⭐⭐☆☆☆ (Facile)

### 3. Multi-facteurs (app04)
Plusieurs mots de passe à trouver, mais tous en clair.
- **Difficulté** : ⭐⭐☆☆☆ (Facile)

### 4. Échantillonnage (app05)
Seuls certains caractères sont vérifiés.
- **Difficulté** : ⭐⭐⭐☆☆ (Moyen)

### 5. XOR simple (app06)
Le mot de passe est chiffré avec une clé XOR constante.
- **Difficulté** : ⭐⭐⭐☆☆ (Moyen)

### 6. Double XOR (app07)
Le mot de passe est obtenu par XOR de deux clés.
- **Difficulté** : ⭐⭐⭐⭐☆ (Difficile)

---

## OUTILS UTILISÉS

### `file`
Identifie le type de fichier et l'architecture.
```bash
file appXX
```

### `strings`
Extrait les chaînes de caractères lisibles d'un binaire.
```bash
strings appXX
```

### `objdump`
Désassemble le code machine en assembleur.
```bash
objdump -d appXX > appXX.asm
```

### `echo` et pipes
Permet de tester les mots de passe automatiquement.
```bash
echo "mot_de_passe" | ./appXX
```
