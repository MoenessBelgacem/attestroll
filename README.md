# Fleetproof (nom de travail) - prototype v0.1

**Mettre à jour une flotte d'appareils IoT en sécurité, et en garder la preuve.**

Prototype fonctionnel du cœur du produit : hub de déploiement + agent d'appareil simulé,
avec signatures, déploiement progressif, arrêt et retour arrière automatiques, SBOM par version,
requête d'exposition aux vulnérabilités et journal d'audit infalsifiable.

> Le nom est provisoire : aucune vérification de disponibilité ou de marque n'a été faite.

## Lancer

```bash
pip install cryptography        # seule dépendance
python -m unittest tests.test_core -v
python demo.py                  # flotte de 200 appareils simulés, 4 scénarios
```

## Ce que le prototype démontre

| Fonction | Où | Preuve |
|---|---|---|
| Versions signées (Ed25519), clé privée côté CI uniquement | `crypto.py`, `publisher.py` | le serveur et les appareils n'ont que la clé publique |
| Les appareils vérifient signature + hash eux-mêmes | `agent.py` | scénario 3 : un serveur compromis ne peut pas imposer une image modifiée |
| Déploiement progressif 5 % → 25 % → 100 % | `state.py` | scénario 1 |
| Arrêt automatique si le taux d'échec dépasse le seuil | `state.py` | scénario 2 : arrêt dès le canari |
| Retour arrière des appareils déjà mis à jour | `state.py` | scénario 2 |
| SBOM signé dans chaque version + « qui est exposé à cette bibliothèque ? » | `state.exposure` | scénarios 0 et 1 : 200/200 puis 0/200 |
| Journal d'audit chaîné par hachage (toute modification est détectée) | `audit.py` | scénario 4 |

## Lien avec le Cyber Resilience Act (CRA) de l'UE

Le CRA impose aux fabricants de traiter les vulnérabilités, de fournir des mises à jour de
sécurité pendant une période de support et de tenir une documentation technique avec SBOM.
Ce prototype produit des **éléments de preuve** pour ces obligations (version installée par
appareil, historique signé, exposition par composant, date de fin de support dans le manifeste).

**Ce n'est pas un avis juridique et ça ne garantit aucune conformité.** À valider avec des
juristes et les textes à jour avant toute promesse commerciale.

## Limites connues (honnêtes)

- Prototype : pas de TLS, jeton admin statique, tout en mémoire (pas de base de données).
- Appareils simulés : pas de vrai firmware, pas de partitions A/B ni de bootloader.
- Le contrôle de santé est une simulation ; en réel, c'est la partie la plus difficile.
- SBOM simplifié écrit à la main ; en réel, il doit être généré automatiquement à la compilation.
- Le seuil d'échec est cumulatif et simple ; une vraie plateforme aura des critères par groupe.
- Pas d'authentification par appareil (à faire : certificats par appareil).
- Aucune donnée de marché ni de demande client n'est validée par ce code.

## Feuille de route : 12 semaines

| Sem. | Objectif | Critère de réussite |
|---|---|---|
| 1 | Agent ESP32 : mise à jour HTTPS avec retour arrière (fonction de rollback d'ESP-IDF, à vérifier dans la doc Espressif) | 1 carte se met à jour et revient seule sur un firmware volontairement cassé |
| 2 | Vérification de la signature Ed25519 sur l'ESP32 | une image non signée est refusée |
| 3 | Agent Linux (Raspberry Pi) | mise à jour signée + retour arrière |
| 4 | Base SQLite, TLS, identité par appareil, rotation de clés | plus aucun état perdu au redémarrage |
| 5-6 | CLI + GitHub Action de publication, génération automatique du SBOM | `git tag` → version signée publiée |
| 7 | Tableau de bord minimal | on voit versions, déploiements, exposition |
| 8 | Documentation, vidéo de démo de 2 min, page de présentation | un inconnu réussit l'installation seul |
| 9 | Lancement public + 10 entretiens avec des fabricants concernés par le CRA | 20 installations, 5 utilisateurs actifs |
| 10-12 | 3 partenaires de conception, test de prix, solution d'encaissement international | 1 client qui paie |

## Questions d'entretien (fabricants de produits connectés vendus dans l'UE)

1. Comment mettez-vous à jour vos appareils aujourd'hui ?
2. Comment comptez-vous prouver vos mises à jour de sécurité d'ici 2027 ?
3. Une mise à jour ratée vous est-elle déjà arrivée ? Coût ?
4. Savez-vous quels composants logiciels tournent sur chaque appareil vendu ?
5. Qu'avez-vous essayé, et pourquoi avez-vous arrêté ?
6. Que paieriez-vous, et sous quelle forme (par appareil, par mois) ?
