# Fleetproof (nom de travail) - prototype v0.2

**Mettre à jour une flotte d'appareils IoT en sécurité, et en garder la preuve.**

Prototype fonctionnel du cœur du produit : hub de déploiement + agent d'appareil simulé,
avec signatures, déploiement progressif, arrêt et retour arrière automatiques, SBOM par version,
requête d'exposition aux vulnérabilités et journal d'audit infalsifiable.

> Le nom est provisoire : aucune vérification de disponibilité ou de marque n'a été faite.

## Lancer

```bash
pip install cryptography        # seule dépendance
python -m unittest discover -s tests -v
python demo.py                  # flotte de 200 appareils simulés, 7 scénarios
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
| Journal d'audit chaîné par hachage (toute modification est détectée) | `audit.py` | scénario 6 |
| Persistance SQLite : un redémarrage ne perd rien, un journal modifié empêche le démarrage | `store.py`, `state.py` | scénario 4 + `test_persistence.py` |
| Identité par appareil : clé privée générée sur l'appareil, enrôlement par jeton à usage unique | `agent.py`, `state.py` | scénario 5 |
| Requêtes signées (identité, verbe, URL, heure, nonce, corps) : usurpation, rejeu et altération refusés | `crypto.py`, `server.py` | scénario 5 + `test_identity.py` |
| Révocation d'un appareil (403) et refus consignés dans l'audit | `state.py` | scénario 5 |

## Lien avec le Cyber Resilience Act (CRA) de l'UE

Le CRA impose aux fabricants de traiter les vulnérabilités, de fournir des mises à jour de
sécurité pendant une période de support et de tenir une documentation technique avec SBOM.
Ce prototype produit des **éléments de preuve** pour ces obligations (version installée par
appareil, historique signé, exposition par composant, date de fin de support dans le manifeste).

**Ce n'est pas un avis juridique et ça ne garantit aucune conformité.** À valider avec des
juristes et les textes à jour avant toute promesse commerciale.

## Limites connues (honnêtes)

- **Pas de TLS** : le serveur parle en HTTP simple. Un vrai déploiement doit placer TLS devant lui. Les signatures protègent l'identité et l'intégrité, pas la confidentialité.
- Jeton admin unique et statique (à remplacer par des comptes, des rôles et une authentification forte).
- Le jeton d'enrôlement doit être remis à l'appareil par un canal sûr, hors du hub (atelier de production, par exemple). Ce canal n'est pas modélisé.
- Le cache anti-rejeu (nonces) est en mémoire : après un redémarrage, un rejeu reste possible pendant la fenêtre de 5 minutes.
- Pas de rotation de clés d'appareil ni de clé de publication.
- SQLite sur un seul serveur : pas de haute disponibilité. L'état d'un déploiement est réécrit en entier à chaque rapport, ce qui ne tiendra pas à des milliers d'appareils sans refonte du stockage.
- Une panne du processus au milieu d'une opération laisse la base cohérente (transactions), mais l'état en mémoire n'est pas rechargé automatiquement après une exception.
- Dans la simulation, la clé privée de l'appareil est en mémoire ; sur un vrai appareil elle doit être en stockage protégé.
- Appareils simulés : pas de vrai firmware, pas de partitions A/B ni de bootloader.
- Le contrôle de santé est une simulation ; en réel, c'est la partie la plus difficile.
- SBOM simplifié écrit à la main ; en réel, il doit être généré automatiquement à la compilation.
- Le seuil d'échec est cumulatif et simple ; une vraie plateforme aura des critères par groupe.
- Aucune donnée de marché ni de demande client n'est validée par ce code.

## Feuille de route : 12 semaines

| Sem. | Objectif | Critère de réussite |
|---|---|---|
| 1 | Agent ESP32 : mise à jour HTTPS avec retour arrière (fonction de rollback d'ESP-IDF, à vérifier dans la doc Espressif) | 1 carte se met à jour et revient seule sur un firmware volontairement cassé |
| 2 | Vérification de la signature Ed25519 sur l'ESP32 | une image non signée est refusée |
| 3 | Agent Linux (Raspberry Pi) | mise à jour signée + retour arrière |
| 4 | ~~Base SQLite, identité par appareil~~ (fait en v0.2) ; reste : TLS, rotation de clés | TLS actif, clé tournée sans perdre de flotte |
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
