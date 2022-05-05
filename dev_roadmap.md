# Roadmap dev

## Restructuration

* Définition des structures à partir du graph d'entry points, définition des rélations entre structures & déduplication des structures
* Typage du desassemblé & décompilé avec nos structures, choix des types les plus adaptés (gestion conflits sur types à appliquer)
* Remise en place du plugin
* Mise en place de tests (non régression automatique ?)
* propagation dans les caller, dans le cas de points d'entrée par allocation dynamique

## Features

* Multi-arch ?
* API permettant d'ajouter des extensions à l'analyse
* typage & nommage de plus de champs au sein des structures créées
* Décompilé: associer une structure à son malloc | Transformation de la taille d'allocation (decimal) en sizeof()
* Regarder l'utilisation du label `__cppobj` sur une structure

## Bugs

* Supprimer le side-effect des **CONTAINING_RECORD** introduits dans le décompilé
* Plugin: option pour annuler une propagation (supprimer le type précédemment appliqué)
* Eviter le typage des fonctions "fourre-tout" (memset typé avec une structure spécifique)
* Ajouter les xrefs sur les opérandes qui n'ont pas été attribuées à une structure, mais où elle peut passer
* Cpustate: faire la différence entre ax et rax
* Cpustate: prendre en compte la taille d'une opérande avant de le convertir de unsigned en signed (ne pas se baser seulement sur `ctypes.c_int32`
