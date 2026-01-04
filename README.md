<!-- ================================================= -->
<!--                    XiwA v2                        -->
<!-- ================================================= -->

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0b0b0b&height=150&section=header&text=XiwA%20v2&fontSize=44&fontColor=ffffff&animation=fadeIn&desc=Modular%20Toolbox%20for%20Analysis%20and%20Security&descAlignY=70"/>

<br/>

![Status](https://img.shields.io/badge/status-active-black?style=flat-square)
![Python](https://img.shields.io/badge/python-3.x-black?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)

</div>

---

## Présentation

**XiwA v2** est un projet modulaire conçu comme une **boîte à outils technique**.  
Il regroupe différents scripts orientés analyse, OSINT et tests techniques, organisés dans une architecture claire et extensible.

Le projet met l’accent sur :
- la séparation des responsabilités
- la lisibilité du code
- la possibilité d’ajouter ou retirer des modules sans impacter l’ensemble

XiwA n’est pas pensé comme un outil monolithique mais comme une base évolutive.

---

## Structure du projet

```
XiwA-v2/
├── main.py
├── programs/
│   ├── EmailLookup.py
│   ├── IPLocalisater.py
│   ├── IPPortScanner.py
│   ├── ImageToExif.py
│   ├── WebsiteWhois.py
│   ├── WebsiteSQLi.py
│   ├── WebsitePhpInfoFinder.py
│   ├── WebsiteShortURL.py
│   ├── PenetrationTest.py
│   ├── PhishingAttack.py
│   ├── GooglePhishingAttack.py
│   └── VirusBuilder.py
├── requirements.txt
└── README.md
```

Chaque fichier dans `programs/` correspond à un module indépendant.

---

## Philosophie

XiwA v2 repose sur quelques principes simples :

- pas de dépendance inutile entre modules
- logique claire et explicite
- code modifiable sans effet de bord
- priorité à la compréhension plutôt qu’à l’obfuscation

Le projet vise à servir de base de travail, d’expérimentation ou d’apprentissage avancé.

---

## Installation

```bash
git clone https://github.com/Dryz3R/XiwA-v2.git
cd XiwA-v2
pip install -r requirements.txt
```

---

## Utilisation

```bash
python main.py
```

Le point d’entrée centralise l’accès aux modules disponibles.

---

## État du dépôt

<div align="center">

<img src="https://github-readme-stats.vercel.app/api?username=Dryz3R&show_icons=true&theme=dark&hide_border=true"/>

<img src="https://github-readme-stats.vercel.app/api/top-langs/?username=Dryz3R&layout=compact&theme=dark&hide_border=true"/>

</div>

---

## Cadre d’utilisation

Ce projet est fourni à des fins :
- éducatives
- expérimentales
- de test en environnement contrôlé

L’utilisateur est seul responsable de l’usage qu’il fait des outils proposés et du respect des lois applicables.

---

## Contribution

Les contributions sont possibles via pull request :

```bash
git checkout -b feature/amelioration
git commit -m "Amélioration ou ajout de module"
git push origin feature/amelioration
```

Merci de documenter clairement toute modification.

---

## Licence

Projet distribué sous licence **MIT**.  
Voir le fichier `LICENSE` pour plus d’informations.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0b0b0b&height=120&section=footer&animation=fadeIn"/>

Développé par Dryz3R  
https://github.com/Dryz3R

</div>
