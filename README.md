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

### Étape 4 : Analyse du code assembleur

**Code important (fonction main) :**
```asm
movl   $0xa,-0x8(%ebp)      # Met 10 dans une variable
movl   $0x63,-0x4(%ebp)     # Met 99 dans une variable
```

**Explication :**
- `0xa` = 10 en hexadécimal → début de la boucle
- `0x63` = 99 en hexadécimal → fin de la boucle
- Le programme affiche les nombres de 10 à 98

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

### Étape 3 : Analyse du code assembleur

**Commande exécutée :**
```bash
objdump -d app02 > app02.asm
```

**Code important trouvé :**
```asm
push   $0x804a00e          # Adresse de "dOxgFpCDHhoa3"
call   strncmp@plt         # Compare avec l'entrée utilisateur
```

**Explication :**
- Le programme compare l'entrée utilisateur avec la chaîne "dOxgFpCDHhoa3"
- `strncmp` : Fonction qui compare deux chaînes de caractères

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

### Étape 3 : Analyse du code assembleur

**Commande exécutée :**
```bash
objdump -d app03 > app03.asm
```

**Code important trouvé dans la fonction check_password :**
```asm
movl   $0x72524c2b,-0x11(%ebp)    # Stocke des octets en mémoire
movl   $0x547a324e,-0xd(%ebp)     # Stocke d'autres octets
movl   $0x47455331,-0x9(%ebp)     # Stocke encore des octets
```

**Explication :**
- Ces valeurs hexadécimales sont stockées en mémoire
- En little-endian (lecture inversée), ça donne :
  - `0x72524c2b` → `2b 4c 52 72` → `+LRr`
  - `0x547a324e` → `4e 32 7a 54` → `N2zT`
  - `0x47455331` → `31 53 45 47` → `1SEG`
- Mot de passe complet : **+LRrN2zT1SEG**

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

### Étape 3 : Analyse du code assembleur

**Commande exécutée :**
```bash
objdump -d app04 > app04.asm
```

**Code important trouvé :**
```asm
# Vérification 1 : username
push   $0x804a008          # "ajacobe"
call   strncmp@plt

# Vérification 2 : password
push   $0x804a010          # "BPYWHwivoYmi"
call   strncmp@plt

# Vérification 3 : TOTP
push   $0x804a01d          # "816201"
call   strncmp@plt
```

**Explication :**
- Le programme vérifie 3 champs dans l'ordre
- Si un champ est incorrect, il s'arrête et affiche l'erreur

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

### Étape 3 : Analyse du code assembleur

**Commande exécutée :**
```bash
objdump -d app05 > app05.asm
```

**Code important trouvé :**
```asm
movl   $0x656a6b74,-0x10(%ebp)    # "tkje"
movl   $0x47783646,-0xc(%ebp)     # "F6xG"
movl   $0x2b7a5758,-0x8(%ebp)     # "XWz+"

# Boucle de vérification
addl   $0x1,-0x18(%ebp)           # i++
addl   $0x2,-0x14(%ebp)           # j += 2  (IMPORTANT!)
```

**Explication :**
- Le mot de passe complet stocké est : `tkjeF6xGXWz+`
- Mais le compteur saute de 2 à chaque fois (`j += 2`)
- Donc seuls les caractères aux positions paires sont vérifiés :
  - Position 0 : `t`
  - Position 2 : `j`
  - Position 4 : `F`
  - Position 6 : `x`
  - Position 8 : `X`
  - Position 10 : `z`
- Mot de passe attendu : **tjFxXz**

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

### Étape 3 : Analyse du code assembleur

**Commande exécutée :**
```bash
objdump -d app06 > app06.asm
```

**Code important trouvé :**
```asm
movl   $0x69586d44,-0x10(%ebp)    # Mot de passe chiffré
movl   $0x497b7718,-0xc(%ebp)     # Suite du mot de passe
movl   $0x515b5462,-0x8(%ebp)     # Fin du mot de passe

xor    $0x21,%edx                 # XOR avec la clé 0x21
```

**Explication :**
- Le mot de passe est chiffré avec un XOR
- Clé XOR : `0x21`
- Pour déchiffrer, on fait : octet chiffré XOR 0x21 = octet clair

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

### Étape 3 : Analyse du code assembleur

**Commande exécutée :**
```bash
objdump -d app07 > app07.asm
```

**Code important trouvé :**
```asm
# Première clé
movl   $0x1e140d6e,-0x18(%ebp)
movl   $0x32133314,-0x14(%ebp)

# Deuxième clé
movl   $0x50226517,-0x10(%ebp)
movl   $0x1694275,-0xc(%ebp)

# XOR entre les deux clés
xor    %ebx,%edx
```

**Explication :**
- Le mot de passe n'est pas stocké directement
- Il y a 2 clés stockées en mémoire
- Le mot de passe = clé1 XOR clé2

**Calcul du mot de passe :**
```
Clé 1 : 6e 0d 14 1e 14 33 13 32
Clé 2 : 17 65 22 50 75 42 69 01

0x6e XOR 0x17 = 0x79 = 'y'
0x0d XOR 0x65 = 0x68 = 'h'
0x14 XOR 0x22 = 0x36 = '6'
0x1e XOR 0x50 = 0x4e = 'N'
0x14 XOR 0x75 = 0x61 = 'a'
0x33 XOR 0x42 = 0x71 = 'q'
0x13 XOR 0x69 = 0x7a = 'z'
0x32 XOR 0x01 = 0x33 = '3'

Mot de passe : yh6Naqz3
```

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
