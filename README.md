# Pool Hockey – Olympiques 2026 (statique, gratuit)

- 15 **joueurs** + 2 **gardiens** par pooler
- Points: **But = 1**, **Passe = 1**, **Victoire gardien = 2** (régulier/OT/TB), **Défaite gardien en OT/TB = 1**, **Blanchissage = 3**
- Sélection **manuelle**, avec option **Règles de boîtes** (B1..B10: 1 chacun, G1:1, G2:1, BONUS:5)
- Mises à jour **toutes les 5 min** via **Google Sheets publié en CSV** ou import manuel

## Démarrage
1. Ouvrir `index.html`.
2. Importer les **joueurs** depuis `assets/players_pool_boxes.csv` (pré-rempli avec tes boîtes) ou coller l’URL CSV d’un Google Sheets.
3. Ajouter les **poolers** (15 skaters / 2 gardiens déjà proposés) et sélectionner.
4. Coller l’URL CSV **stats** et activer *Rafraîchir automatiquement (5 min)*.

## Format CSV – joueurs (avec boîtes)

```csv
name,position,team,box
Connor McDavid,F,CAN,B1
Quinn Hughes,D,USA,B2
Jordan Binnington,G,CAN,G1
...
```

`position` ∈ {F,D,G} ; `team` = code pays (CAN, USA, SWE, FIN, etc.) ; `box` ∈ {B1..B10, G1, G2, BONUS}

## Format CSV – statistiques quotidiennes

```csv
date,player,goals,assists,goalie_win,goalie_otl,shutout
2026-02-11,Juraj Slafkovsky,1,1,0,0,0
2026-02-11,Samuel Hlavaj,0,0,1,0,0
```

- Les noms doivent correspondre à la **liste maîtresse**.

## Déploiement
GitHub Pages → Paramètres → Pages → Source **main** / **root**.

## Notes
- Pas d’API officielle publique JO/IIHF pour stats par joueur → utiliser Google Sheets publié pour un suivi gratuit fiable. Voir le calendrier/résultats officiels sur [olympics.com](https://www.olympics.com/en/milano-cortina-2026/schedule/iho) et la stats page IIHF (tournois) pour recouper. 
