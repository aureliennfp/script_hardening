# Scripts de durcissement Linux

Deux scripts bash de durcissement (hardening). Ils fonctionnent par étapes indépendantes et ré-exécutables. Une étape qui échoue est notée et le script continue. Un audit [Lynis](https://cisofy.com/lynis/) est lancé avant et après, pour mesurer le gain.

| Script | Cible | Contexte |
| --- | --- | --- |
| [`hardening-acme-ubuntu.sh`](hardening-acme-ubuntu.sh) | VM Ubuntu Server 22.04 / 24.04 | SAÉ ACME (BUT Informatique 3e année) : serveur web nginx en DMZ, serveur Wazuh |
| [`hardening-lxc.sh`](hardening-lxc.sh) | Conteneurs LXC Debian / Ubuntu sous Proxmox | Homelab : Apache/PHP, FreshRSS, Vaultwarden, Uptime Kuma, MySpeed, Docker |

> **Avant de lancer un script, faites un snapshot de la machine.** Chaque script sauvegarde aussi `/etc` dans `/root/...` avant de modifier quoi que ce soit.

Si le fichier a transité par Windows, convertissez d'abord les fins de ligne :

```bash
sed -i 's/\r$//' <script>.sh && chmod +x <script>.sh
```

---

## `hardening-acme-ubuntu.sh` - VM Ubuntu

Trois rôles : `base` (socle commun), `web` (nginx) et `wazuh` (serveur Wazuh all-in-one).

```bash
# Serveur web (site vitrine nginx)
sudo ./hardening-acme-ubuntu.sh --role web --admin-pubkey ~/id_ed25519.pub \
     --admin-net 10.10.20.0/24 --deploy-vhost --site-name www.acme.local \
     --wazuh-manager <IP_WAZUH>

# Serveur Wazuh
sudo ./hardening-acme-ubuntu.sh --role wazuh --admin-pubkey ~/id_ed25519.pub \
     --admin-net 10.10.20.0/24 --agent-nets 10.10.20.0/24,10.10.30.0/24

# Seulement certaines étapes
sudo ./hardening-acme-ubuntu.sh --role web --steps 4,5
```

| Étape | Contenu |
| --- | --- |
| 0 / 16 | Audit Lynis avant / après, ports en écoute, services |
| 1 - 2 | Sauvegarde de `/etc`, mises à jour, mises à jour de sécurité automatiques (paquets Wazuh gelés) |
| 3 | Comptes : pwquality (12 caractères), verrouillage (faillock), historique, sudo journalisé, `su` interdit |
| 4 | SSH : clés, algorithmes modernes, groupe `ssh-users`, pas de root ; mot de passe conservé tant qu'aucune clé n'existe |
| 5 | Pare-feu UFW : refus par défaut, flux selon le rôle, la session SSH en cours n'est jamais coupée |
| 6 - 8 | Noyau (sysctl, modules, core dumps), `/tmp` et `/dev/shm` en noexec, services inutiles, bannières |
| 9 - 11 | journald persistant, auditd (règles inspirées du CIS), fail2ban, AppArmor |
| 12 | nginx : TLS 1.2/1.3, en-têtes de sécurité, version masquée, limitation de débit, sandbox systemd |
| 13 - 14 | Serveur Wazuh (vérifications, syslog du pare-feu) / agent Wazuh |
| 15 | AIDE (optionnel) |

Le compte utilisé par défaut est celui qui lance `sudo` ; aucun compte n'est créé (`--admin NOM` pour en choisir un autre). Les rapports (Lynis, règles UFW, binaires SUID, en-têtes HTTPS) sont écrits dans `/root/acme-hardening/<date>/`.

Référentiels : CIS Ubuntu Linux Benchmark, profil TLS Mozilla, algorithmes SSH recommandés par l'ANSSI. Une partie seulement des recommandations ANSSI-BP-028 est couverte.

---

## `hardening-lxc.sh` - conteneurs LXC

Un seul script pour tous les conteneurs. Il détecte les services via systemd (dossier de travail, fichier d'environnement, ports réellement en écoute) et n'applique que ce qui les concerne.

```bash
# Depuis l'hôte Proxmox
pct snapshot <CTID> avant-hardening
pct push <CTID> hardening-lxc.sh /root/hardening-lxc.sh
pct enter <CTID>
./hardening-lxc.sh                 # services accessibles depuis le réseau local
./hardening-lxc.sh --cloudflare    # services publiés via Cloudflare Tunnel (vraie IP dans les journaux)

# Audit de tous les conteneurs, en lecture seule, sur l'hôte
./hardening-lxc.sh --host-audit
```

| Étape | Contenu |
| --- | --- |
| 0 - 3 | Détection, audit Lynis, sauvegarde, mises à jour, comptes et sessions |
| 4 | SSH désactivé s'il ne sert pas (`pct enter` suffit), sinon clé uniquement |
| 5 - 7 | sysctl réseau du conteneur, pare-feu nftables, Postfix en local uniquement, journaux |
| 8 | Apache + PHP : version masquée, en-têtes, `mod_status` / `autoindex` désactivés |
| 9 | FreshRSS : DocumentRoot sur `p/`, code en lecture seule, authentification vérifiée |
| 10 | Vaultwarden : inscriptions fermées, indices désactivés, `ADMIN_TOKEN` vérifié |
| 11 | Compte dédié + sandbox systemd pour Vaultwarden, Uptime Kuma, MySpeed |
| 12 - 13 | Rapport Docker (`--docker-harden` pour durcir le démon), vérifications |

Garde-fous :

- Chaque service modifié est redémarré puis vérifié : il doit être actif et écouter à nouveau sur ses ports. En cas d'échec, le script essaie une sandbox allégée, puis restaure la configuration d'origine.
- Le pare-feu n'ouvre que les ports des services détectés et liste ceux qu'il bloque (`--extra-ports` pour en ajouter). Il génère aussi les règles équivalentes pour le pare-feu Proxmox, que root dans le conteneur ne peut pas désactiver.
- L'accès reste toujours possible depuis l'hôte avec `pct enter <CTID>`.

Ce qui ne se règle pas depuis un conteneur (paramètres noyau, conteneur privilégié, AppArmor, nesting) est vérifié par `--host-audit`.

Options utiles : `--allow-from CIDR`, `--admin-net CIDR`, `--tunnel-ip IP` (cloudflared dans un autre conteneur), `--ssh auto|harden|off`, `--no-sandbox`, `--steps 6`. Liste complète : `./hardening-lxc.sh --help`.
