# Why not a Sandbox ?

## intitulé
Votre but est d'appeler la fonction print_flag pour afficher le flag.

## Analyse
Ce challenge est un classique des ctfs, il s'agit d'essayer de s'échapper d'une "jail" python : certaines fonctions sont accessibles, d'autres non. Il faut généralement essayer d'executer une action interdite comme d'appeler un shell.

On va commencer par voir ce qu'on peut faire. 
```>>> import os
Exception ignored in audit hook:
Exception: Action interdite
Exception: Module non autorisé```

Les imports semblent interdits. Mais, curieusement pas tous :
```>>> import io
>>> import posix
>>> import ctypes```

Et encore plus curieusement, l'import de la lib "os" après avoir importé ctypes est tout d'un coup autorisée :
```>>> import os```

Evidement l'appel à la commande system est interdite, ça serait trop simple :
```>>> os.system("/bin/bash")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
```

mais pas spawnv :
```os.spawnv(file="/bin/bash", args=["/bin/bash"], mode="w")
>>> bash: cannot set terminal process group (5128): Inappropriate ioctl for device
bash: no job control in this shell
ctf@whynotasandbox:/app$ ls -al
total 40
drwxr-xr-x 1 root     root  4096 May  2 10:10 .
drwxr-xr-x 1 root     root  4096 May  2 10:11 ..
-r-------- 1 ctf-init ctf  16064 May  2 10:10 lib_flag.so
-r-sr-x--- 1 ctf-init ctf  14904 May  2 10:10 spython
```

On imagine alors que la fonction print_flag doit se cacher dans le fichier "lib_flag.so". Problème, il n'est pas lisible par l'utilisateur actuel (ctf).

Autre point interessant : le binaire **spython** qui est en [suid](https://fr.wikipedia.org/wiki/Setuid), c'est à dire qu'il peut être lancé par les membres du groupe *ctf* avec les droits de l'utilisateur *ctf-init*. C'est ce binaire qui est lancé et qui est chargé de gerer la "jail" dans laquelle nous sommes. La librairie *lib_flag.so* est automatiquement chargée par ce binaire.

Après quelques recherches, on tombe sur [cette page](https://www.python.org/dev/peps/pep-0578/#why-not-a-sandbox) dont un paragraphe a visiblement inspiré le nom du challenge. Nous avons donc affaire à un **Runtime Audit Hooks Python** (une nouveauté python 3.8) qui est fait pour analyser le comportement d'un programme python et de loguer les actions suspectes, mais certainement pas de réaliser une "jail" python efficace (Ce qui d'ailleurs est extrèmement compliqué)

J'ai également trouvé un article interessant à ce sujet, [qui indique comment casser ce type de jail sur Windows](https://daddycocoaman.dev/posts/bypassing-python38-audit-hooks-part-1/). Je m'en suis inspiré pour faire de même. 

La suite de l'exploit consiste à déproteger la zone mémoire où est stockée la fonction *PySys_Audit()* pour qu'elle soit accessible en écriture. Puis à patcher cette fonction pour qu'elle ne fasse que l'équivalent d'un `return 0`

On est ensuite libre de réaliser toutes les actions possibles, notamment charger la librairie "lib_flag.so" et d'appeler la fonction print_flag() qui affiche le flag.

Pour plus de détails, [le code que j'ai utilisé](exploit.py) .


