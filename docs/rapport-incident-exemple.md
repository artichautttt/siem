# Rapport d'incident — Brute Force SSH

## Résumé

Le Mini-SIEM a détecté une tentative de brute force sur le service SSH d'un
hôte interne. La règle `Brute Force SSH` s'est déclenchée après 7 tentatives
de connexion refusées (DENY) sur le port 22, depuis une même adresse IP
source, en moins de 5 minutes. L'alerte a été classée en sévérité
**CRITICAL** et a contribué significativement au score de risque global de la
fenêtre analysée.

## Détails de l'alerte

| Champ            | Valeur |
|-------------------|--------|
| Règle déclenchée  | Brute Force SSH |
| IP source         | 45.33.32.156 |
| IP destination    | 192.168.1.14 (serveur applicatif interne) |
| Port ciblé        | 22/TCP (SSH) |
| Sévérité          | CRITICAL |
| Horodatage        | 2026-09-11T02:14:07Z (première tentative), 2026-09-11T02:14:52Z (7ᵉ tentative, seuil atteint) |
| Nombre de tentatives | 7 en 45 secondes |
| Action système    | DENY (bloqué par la règle de firewall/IDS en amont) |

## Contexte et investigation

Démarche qu'un analyste SOC suivrait avant de clôturer ou d'escalader
l'alerte :

1. **Réputation et géolocalisation de l'IP source** — 45.33.32.156 est déjà
   référencée dans la liste des IP connues malveillantes (`KNOWN_BAD_IPS`) du
   Mini-SIEM ; une vérification croisée sur des bases de threat intelligence
   externes (AbuseIPDB, Shodan, VirusTotal) confirmerait un historique de
   scan/brute force associé à cette IP.
2. **Recherche d'autres tentatives associées** — recherche dans les logs
   (`GET /api/search?q=45.33.32.156`) sur une fenêtre plus large (24-48h)
   pour vérifier si l'IP a ciblé d'autres hôtes ou services (corrélation avec
   une règle Port Scan ou Accès Critique sur la même source).
3. **Vérification côté hôte cible** — sur 192.168.1.14, consultation des logs
   d'authentification SSH (`/var/log/auth.log` ou équivalent) pour confirmer
   qu'aucune tentative n'a abouti (pas de compromission de compte), et
   identification des comptes ciblés.
4. **Vérification de la surface exposée** — confirmation que le port 22 ne
   devrait pas être accessible depuis Internet sur cet hôte, ou qu'un accès
   VPN/bastion est requis en amont.
5. **Recherche de faux positifs** — élimination d'une explication bénigne
   (ex : scan de vulnérabilité autorisé, script d'intégration mal configuré)
   avant de qualifier l'alerte de malveillante.

Aucune connexion SSH réussie n'a été trouvée dans les logs pour cette IP sur
la période analysée : l'attaque est jugée **non aboutie**.

## Sévérité assignée et justification

**CRITICAL**, conformément à la classification du moteur de détection
(`detector.py::rule_brute_force_ssh`) : un brute force SSH ciblant un serveur
interne représente un vecteur d'accès initial direct (Credential Access) qui,
en cas de succès, permettrait un accès shell complet à l'hôte. Le volume de
tentatives (7 en 45 secondes) et la présence de l'IP dans la liste des IP
connues malveillantes renforcent la confiance dans la détection (faible
probabilité de faux positif).

## Recommandations

- **Bloquer l'IP source au niveau du pare-feu périmétrique** (règle DENY
  permanente sur 45.33.32.156), au-delà du blocage déjà appliqué au niveau
  applicatif.
- **Forcer la rotation des clés/mots de passe SSH** sur l'hôte ciblé par
  précaution, même en l'absence de compromission confirmée.
- **Activer l'authentification multi-facteurs (MFA)** sur l'accès SSH, ou a
  minima désactiver l'authentification par mot de passe au profit de clés
  publiques uniquement.
- **Mettre en place un fail2ban (ou équivalent)** pour bannir automatiquement
  les IP après un nombre limité d'échecs, en complément de la détection SIEM.
- **Restreindre l'exposition du port 22** à des IP/VPN de confiance via
  liste blanche, plutôt que de l'exposer largement.
- **Surveiller l'IP source** sur les prochaines 72h pour détecter une
  éventuelle reprise d'activité ou un changement de cible.

## Mapping MITRE ATT&CK

- **Tactique** : Credential Access
- **Technique** : T1110 — Brute Force

## Statut

**Résolu** — IP bloquée au pare-feu, aucune compromission confirmée sur
l'hôte cible, surveillance renforcée activée pour 72h.
