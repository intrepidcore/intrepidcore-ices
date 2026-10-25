# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Serge TABE DJATO
"""Figures du livre blanc ICES v4.0, conformes au guide de rédaction v7.0.

- format vectoriel (PDF, polices incorporées), police Times New Roman ;
- aucun titre dans l'image : le titre déclaratif est dans la légende LaTeX ;
- échelles qualitatives en mots, jamais un chiffre sans source ;
- un état n'est jamais codé par la seule couleur (mot ou forme associé).

Usage : python make_figures.py   (écrit les PDF à côté du script)
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap
from matplotlib.patches import Polygon

OUT = Path(__file__).resolve().parent

INTREPID, ACCENT, CYAN, VERT, ROUGE, GRIS = "#00396B", "#D55D24", "#00C4D4", "#40916C", "#C62828", "#787878"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "TeX Gyre Termes", "DejaVu Serif"],
    "font.size": 9.5,
    "pdf.fonttype": 42,
    "axes.edgecolor": "#333333",
    "axes.linewidth": 0.8,
    "axes.grid": True,
    "grid.color": "#DDDDDD",
    "grid.linewidth": 0.6,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
})
W = 6.2  # largeur du texte en pouces (15,8 cm)


def enregistrer(nom):
    plt.savefig(OUT / f"{nom}.pdf", bbox_inches="tight", pad_inches=0.04)
    plt.close()
    print("ok", nom)


# 1. Traçabilité au fil des phases d'un marché
fig, ax = plt.subplots(figsize=(W, 3.1))
phases = ["Étude\n(APD)", "Exécution\n(EXE)", "Chantier", "Réception"]
x = np.arange(4)
sans, avec = [3, 2, 1, 0], [3, 3, 3, 3]
ax.plot(x, avec, marker="o", color=VERT, lw=2.2, zorder=4, label="Avec ICES : chaîne scellée")
ax.plot(x, sans, marker="s", color=ROUGE, lw=2.2, ls="--", zorder=4, label="Sans ICES : rupture à chaque transition")
ax.fill_between(x, sans, avec, color=ROUGE, alpha=0.07, zorder=1)
ax.set_xticks(x); ax.set_xticklabels(phases)
ax.set_yticks([0, 1, 2, 3]); ax.set_yticklabels(["rompue", "faible", "partielle", "établie"])
ax.set_ylim(-0.4, 3.6)
ax.set_ylabel("Traçabilité du dossier\n(échelle qualitative, non mesurée)")
ax.legend(loc="lower left", frameon=False)
ax.spines[["top", "right"]].set_visible(False)
enregistrer("fig_airgap")

# 2. Les trois garanties
fig, ax = plt.subplots(figsize=(W, 2.9))
niveaux = ["nulle", "faible", "conditionnelle", "forte"]
rows = [("Intégrité du calcul", 3, INTREPID, "sous deux hypothèses : résistance de SHA3-256 aux collisions, inforgeabilité d'Ed25519"),
        ("Attribution", 2, ACCENT, "conditionnée à la gouvernance du registre de confiance"),
        ("Véracité physique", 0, ROUGE, "nulle par construction : traitée hors de la cryptographie")]
for i, (nom, v, col, note) in enumerate(rows):
    y = len(rows) - 1 - i
    ax.barh(y, 3, color="#ECECEC", height=0.46, zorder=2)
    ax.barh(y, max(v, 0.06), color=col, height=0.46, zorder=3)
    ax.text(-0.05, y, nom, ha="right", va="center")
    ax.text(0.02, y - 0.40, note, ha="left", va="center", fontsize=8, color="#444")
ax.set_xlim(0, 3.05); ax.set_ylim(-0.75, 2.4)
ax.set_xticks([0, 1, 2, 3]); ax.set_xticklabels(niveaux)
ax.set_yticks([])
ax.set_xlabel("Force de la garantie (échelle qualitative)")
ax.spines[["top", "right", "left"]].set_visible(False)
ax.yaxis.grid(False)
plt.subplots_adjust(left=0.2)
enregistrer("fig_guarantees")

# 3. Déplacement du coût de la fraude
fig, ax = plt.subplots(figsize=(W, 2.9))
dims = ["Attribution personnelle\nd'une décision", "Détectabilité d'une\naltération de dossier", "Preuve directement\nexploitable en justice"]
sans, avec = [1, 1, 1], [3, 3, 2]
y = np.arange(3); h = 0.36
ax.barh(y + h / 2, sans, height=h, color=GRIS, label="Sans ICES", zorder=3)
ax.barh(y - h / 2, avec, height=h, color=INTREPID, label="Avec ICES", zorder=3)
ax.set_yticks(y); ax.set_yticklabels(dims)
ax.invert_yaxis()
ax.set_xlim(0, 3.3); ax.set_xticks([1, 2, 3]); ax.set_xticklabels(["faible", "moyenne", "élevée"])
ax.set_xlabel("Échelle qualitative, à titre illustratif, non mesurée")
ax.legend(loc="lower right", frameon=False)
ax.spines[["top", "right"]].set_visible(False)
ax.yaxis.grid(False)
enregistrer("fig_fraudcost")

# 4. Fenêtre d'exploitation d'une clé volée
fig, ax = plt.subplots(figsize=(W, 2.8))
ax.broken_barh([(0, 24)], (2.4, 0.7), facecolors="#E8E8E8", edgecolor="#BBB", zorder=2)
ax.broken_barh([(6, 18)], (2.4, 0.7), facecolors=ROUGE, alpha=0.8, zorder=3)
ax.text(-0.4, 2.75, "Clé à longue durée,\nsans révocation", ha="right", va="center")
ax.text(15, 2.75, "faux valides indéfiniment", ha="center", va="center", color="white")
ax.broken_barh([(0, 24)], (0.6, 0.7), facecolors="#E8E8E8", edgecolor="#BBB", zorder=2)
ax.broken_barh([(6, 1.4)], (0.6, 0.7), facecolors=ROUGE, alpha=0.8, zorder=3)
ax.broken_barh([(7.4, 16.6)], (0.6, 0.7), facecolors=VERT, alpha=0.55, zorder=3)
for t in range(0, 25, 2):
    ax.plot([t, t], [0.6, 1.3], color="#999", lw=0.5, zorder=4)
ax.text(-0.4, 0.95, "Clé courte, rotation\net révocation", ha="right", va="center")
ax.text(15.7, 0.95, "clé révoquée : plus de faux", ha="center", va="center", fontsize=8.5, zorder=6, bbox=dict(facecolor="white", edgecolor="none", pad=2.0))
ax.annotate("vol de la clé", xy=(6, 3.1), xytext=(6, 3.75), ha="center",
            arrowprops=dict(arrowstyle="->", color="#222", lw=0.9))
ax.set_xlim(-0.2, 24.5); ax.set_ylim(0, 4.1)
ax.set_yticks([]); ax.set_xticks(range(0, 25, 4))
ax.set_xlabel("Temps, en unités de rotation (schéma illustratif)")
ax.spines[["top", "right", "left"]].set_visible(False)
ax.xaxis.grid(False)
plt.subplots_adjust(left=0.25)
enregistrer("fig_keywindow")

# 5. Validité à long terme et re-ancrage
fig, ax = plt.subplots(figsize=(W, 2.7))
ax.broken_barh([(2026, 12)], (1.6, 0.7), facecolors=INTREPID, alpha=0.9, zorder=3)
ax.broken_barh([(2038, 28)], (1.6, 0.7), facecolors=VERT, alpha=0.75, zorder=3)
ax.text(2032, 1.95, "Ed25519", ha="center", va="center", color="white")
ax.text(2052, 1.95, "algorithme post-quantique", ha="center", va="center", color="white")
ax.axvspan(2035, 2045, color=ROUGE, alpha=0.10, zorder=1)
ax.text(2040, 2.8, "fenêtre de menace quantique\n(estimation 2035 à 2045)", ha="center", fontsize=8.5, color=ROUGE)
for yr in [2030, 2034, 2037]:
    ax.plot([yr, yr], [1.6, 2.3], color="#333", lw=0.8, zorder=4)
    ax.plot(yr, 2.3, marker="v", color="#333", markersize=5, zorder=5)
ax.text(2033.5, 1.15, "re-ancrages périodiques\n(contre-signature)", ha="center", fontsize=8.5)
ax.annotate("émission\ndu sceau", xy=(2026, 1.6), xytext=(2027, 0.65), ha="left", fontsize=8.5,
            arrowprops=dict(arrowstyle="->", color="#222", lw=0.9))
ax.set_xlim(2024, 2067); ax.set_ylim(0.4, 3.3)
ax.set_yticks([]); ax.set_xlabel("Année")
ax.set_xticks([2026, 2036, 2046, 2056, 2066])
ax.spines[["top", "right", "left"]].set_visible(False)
ax.xaxis.grid(False)
enregistrer("fig_ltv")

# 6. Hiérarchie des preuves de terrain
fig, ax = plt.subplots(figsize=(W, 3.3))
tiers = [("Photo géotaguée déclarative\n(métadonnée EXIF)", GRIS, "corroborante seulement"),
         ("Capture par dispositif attesté\n(GPS et horloge verrouillés)", ACCENT, "probante sous conditions"),
         ("Preuve matérielle de l'instrument\n(journal de la machine d'épreuve)", VERT, "probante")]
n = len(tiers)
def demi_largeur(v):
    return 3.5 + (1.7 - 3.5) * (v / n)
for i, (label, col, poids) in enumerate(tiers):
    yb, yt = i * 1.0, i * 1.0 + 0.9
    ax.add_patch(Polygon([(-demi_largeur(yb), yb), (demi_largeur(yb), yb), (demi_largeur(yt), yt), (-demi_largeur(yt), yt)],
                         closed=True, facecolor=col, edgecolor="white", lw=1.5, zorder=3))
    ax.text(0, (yb + yt) / 2 + 0.12, label, ha="center", va="center", color="white", fontsize=8.8, zorder=4)
    ax.text(0, (yb + yt) / 2 - 0.27, poids, ha="center", va="center", color="white", fontsize=8, style="italic", zorder=4)
ax.annotate("", xy=(4.2, n * 0.95), xytext=(4.2, 0.1), arrowprops=dict(arrowstyle="-|>", color="#333", lw=1.4))
ax.text(4.5, n / 2, "poids probant croissant", rotation=90, va="center", fontsize=9)
ax.set_xlim(-4.0, 5.0); ax.set_ylim(-0.1, n + 0.1)
ax.axis("off")
enregistrer("fig_evidence")

# 7. Spectre des modèles de confiance
fig, ax = plt.subplots(figsize=(W, 2.3))
ax.annotate("", xy=(1.02, 0.5), xytext=(-0.02, 0.5), arrowprops=dict(arrowstyle="-|>", color="#333", lw=1.6))
ax.text(0.0, 0.28, "Centralisé", ha="center", fontsize=8.8)
ax.text(1.0, 0.28, "Décentralisé", ha="center", fontsize=8.8)
pts = [(0.08, "Boîte noire\npropriétaire", GRIS), (0.40, "ICES à l'amorçage\n(fédéré, journal\nà ajout seul)", ACCENT),
       (0.66, "ICES à la cible\n(gouvernance\npublique cédée)", VERT), (0.94, "Registre public\nsans autorité", GRIS)]
for xp, label, col in pts:
    ax.plot(xp, 0.5, marker="o", markersize=11, color=col, zorder=4)
    ax.text(xp, 0.68, label, ha="center", va="bottom", fontsize=8.5)
ax.set_xlim(-0.08, 1.08); ax.set_ylim(0.1, 1.25)
ax.axis("off")
enregistrer("fig_trust")

# 8. Couverture du modèle de menace
fig, ax = plt.subplots(figsize=(W, 3.3))
menaces = ["Altération d'un dossier scellé", "Vol d'une clé de signature", "BCT ou témoin corrompu",
           "Substitution physique de matériau", "Faille de l'implémentation", "Adversaire quantique (2035 à 2045)"]
cols = ["Détection", "Réponse"]
grille = np.array([[2, 2], [1, 2], [1, 1], [0, 1], [1, 2], [0, 1]])
ax.imshow(grille, cmap=ListedColormap([GRIS, ACCENT, VERT]), vmin=0, vmax=2, aspect="auto")
mots = {0: "faible", 1: "partielle", 2: "forte"}
for i in range(len(menaces)):
    for j in range(2):
        ax.text(j, i, mots[grille[i, j]], ha="center", va="center", color="white", fontsize=9)
ax.set_xticks(range(2)); ax.set_xticklabels(cols)
ax.set_yticks(range(len(menaces))); ax.set_yticklabels(menaces)
ax.set_xticks(np.arange(-.5, 2, 1), minor=True); ax.set_yticks(np.arange(-.5, len(menaces), 1), minor=True)
ax.grid(which="minor", color="white", linewidth=2); ax.grid(which="major", visible=False)
ax.tick_params(which="minor", length=0)
plt.subplots_adjust(left=0.38)
enregistrer("fig_threat")

# 9. Bénéfices et coûts par catégorie d'acteur
fig, ax = plt.subplots(figsize=(W, 3.0))
acteurs = ["Bailleur de fonds", "État maître d'ouvrage", "Assureur décennal", "Bureau d'études de bonne foi",
           "Bureau de contrôle technique", "Éditeur concurrent de bonne foi", "Entreprise qui falsifie"]
vals = [3, 3, 2, 2, 1, 1, -3]
y = np.arange(len(acteurs))
ax.barh(y, vals, color=[VERT if v >= 0 else ROUGE for v in vals], height=0.6, zorder=3)
for yi, v in zip(y, vals):
    ax.text(v + (0.1 if v >= 0 else -0.1), yi, "bénéfice" if v > 0 else "coût", va="center",
            ha="left" if v >= 0 else "right", fontsize=8.3)
ax.set_yticks(y); ax.set_yticklabels(acteurs)
ax.invert_yaxis(); ax.axvline(0, color="#333", lw=0.9)
ax.set_xlim(-4.6, 4.4); ax.set_xticks([])
ax.set_xlabel("Échelle qualitative, à titre illustratif, non mesurée")
ax.spines[["top", "right", "left", "bottom"]].set_visible(False)
ax.grid(False)
enregistrer("fig_incentives")

# 10. Feuille de route indicative (mois écoulés depuis la publication du 2 novembre 2026)
fig, ax = plt.subplots(figsize=(W, 3.2))
phases = [("Phase 0 : standard bien public", 0, 6, INTREPID), ("Phase 1 : ingénierie conventionnelle", 4, 9, ACCENT),
          ("Phase 2 : attribution (clés, horodatage)", 6, 11, CYAN), ("Phase 3 : responsabilité et confiance publique", 8, 14, VERT),
          ("Phase 4 : solveur commercial distinct", 6, 18, ROUGE), ("Phase 5 : standard sectoriel", 16, 24, GRIS)]
for i, (label, a, b, c) in enumerate(phases):
    ax.barh(i, b - a, left=a, color=c, height=0.5, edgecolor="white", linewidth=0.6, zorder=3)
    ax.text(a + (b - a) / 2, i, f"M{a} à M{b}", ha="center", va="center", color=("#002" if c == CYAN else "white"), fontsize=7.8, zorder=4)
ax.set_yticks(np.arange(6)); ax.set_yticklabels([p[0] for p in phases], fontsize=8.5)
ax.invert_yaxis()
ticks = [0, 3, 6, 9, 12, 15, 18, 21, 24]
labs = ["nov.\n2026", "févr.\n2027", "mai\n2027", "août\n2027", "nov.\n2027", "févr.\n2028", "mai\n2028", "août\n2028", "nov.\n2028"]
ax.set_xticks(ticks); ax.set_xticklabels(labs, fontsize=8)
ax.set_xlim(0, 24)
ax.spines[["top", "right"]].set_visible(False)
ax.xaxis.grid(True); ax.yaxis.grid(False)
plt.subplots_adjust(left=0.4)
enregistrer("fig_roadmap")
