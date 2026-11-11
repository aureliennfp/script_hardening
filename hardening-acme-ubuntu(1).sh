#!/usr/bin/env bash
# =============================================================================
#  hardening-acme-ubuntu.sh  -  Durcissement des serveurs Ubuntu du SI ACME
#  SAÉ 5.Deploi.01 - BUT Informatique 3e année - IUT de Metz
#
#  Cibles : Ubuntu Server 22.04 LTS / 24.04 LTS
#     --role web    -> ACME-SRV  (site vitrine nginx, DMZ)
#     --role wazuh  -> WAZUH     (serveur Wazuh all-in-one)
#     --role base   -> tout autre serveur Ubuntu (socle commun uniquement)
#
#  Même logique que Hardening-ACME-v3.ps1 :
#     - étapes indépendantes et ré-exécutables (--steps)
#     - une étape qui échoue est notée, le script continue, récapitulatif à la fin
#     - sauvegarde de /etc avant toute modification
#     - audit Lynis AVANT (étape 0) et APRÈS (étape 16) -> preuves pour la notice
#
#  Étapes :
#     0  Audit initial Lynis (score "avant")
#     1  Sauvegarde de /etc + paquets prérequis
#     2  Mises à jour + mises à jour de sécurité automatiques
#     3  Comptes, mots de passe, sudo, su, verrouillage (pwquality, faillock)
#     4  SSH (clés, algorithmes modernes, groupe autorisé, bannière)
#     5  Pare-feu UFW (deny by default, flux par rôle)
#     6  Noyau (sysctl, modules inutiles, core dumps)
#     7  Systèmes de fichiers et permissions (/tmp, /dev/shm, cron, rapports SUID)
#     8  Services et paquets inutiles, bannières légales
#     9  Journalisation et audit (journald, auditd + règles type CIS)
#     10 Fail2ban (SSH + nginx)
#     11 AppArmor
#     12 Rôle web : nginx (TLS, en-têtes, masquage version, rate limit, sandbox systemd)
#     13 Rôle wazuh : pare-feu des flux Wazuh, contrôles de configuration
#     14 Agent Wazuh (si --wazuh-manager est fourni)
#     15 AIDE - intégrité des fichiers (OPTIONNEL, redondant avec le FIM de Wazuh)
#     16 Vérifications + audit final Lynis (score "après")
#
#  AVANT DE LANCER : snapshot de la VM depuis l'hôte Proxmox, par exemple
#       qm snapshot 102 avant-hardening --description "Avant script hardening"
#  et garder la console Proxmox (noVNC) ouverte en cas de souci SSH.
#
#  Exemples :
#    sudo ./hardening-acme-ubuntu.sh --role web --admin-pubkey ~/id_ed25519.pub \
#         --wazuh-manager 10.10.20.30 --deploy-vhost --site-name www.acme.local
#    sudo ./hardening-acme-ubuntu.sh --role wazuh --agent-nets 10.10.0.0/16 --fw-syslog 10.10.20.1
#    sudo ./hardening-acme-ubuntu.sh --role web --steps 4,5      # uniquement SSH et pare-feu
# =============================================================================

set -uo pipefail
VERSION="1.0"

# -----------------------------------------------------------------------------
#  Paramètres par défaut (À ADAPTER au plan d'adressage du groupe)
# -----------------------------------------------------------------------------
ROLE="base"
STEPS_ARG=""
ADMIN_USER=""                      # vide = compte existant qui lance "sudo" (aucun compte créé)
ADMIN_PUBKEY=""                    # clé publique SSH (texte ou chemin de fichier)
ADMIN_NET="10.10.20.0/24"          # réseau(x) d'administration autorisé(s) en SSH, séparés par des virgules
SSH_PORT="22"
NTP_SERVERS=""                     # ex. "10.10.20.1" (OPNsense) - évite un flux DMZ -> AD
WAZUH_MANAGER=""                   # IP du serveur Wazuh (étape 14)
WAZUH_GROUP="default"
WAZUH_VERSION=""                   # ex. "4.12.0-1" pour aligner l'agent sur le manager
AGENT_NETS="10.10.0.0/16"          # rôle wazuh : réseaux d'où viennent les agents (LAN + DMZ)
FW_SYSLOG=""                       # rôle wazuh : IP d'ACME-FW01 pour recevoir son syslog (514/udp)
SITE_NAME="www.acme.local"
WEB_ROOT="/var/www/html"
DEPLOY_VHOST=0
DISABLE_IPV6=0
ASSUME_YES=0

usage() {
    sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'
Options :
  --role base|web|wazuh      rôle du serveur (défaut : base)
  --steps LISTE              ex. "0-11,16" ou "4,5" (défaut : selon le rôle)
  --admin NOM                compte admin (défaut : le compte qui lance sudo ; créé seulement s'il n'existe pas)
  --admin-pubkey CLÉ|FICHIER clé publique SSH du compte admin
  --admin-net CIDR[,CIDR]    réseau(x) autorisé(s) en SSH (défaut : 10.10.20.0/24)
  --ssh-port N               port SSH (défaut : 22)
  --ntp "IP [IP]"            serveur(s) NTP internes
  --wazuh-manager IP         installe et enrôle l'agent Wazuh
  --wazuh-group NOM          groupe d'agents Wazuh (défaut : default)
  --wazuh-version VER        version exacte de l'agent (ex. 4.12.0-1)
  --agent-nets CIDR[,CIDR]   rôle wazuh : réseaux des agents (défaut : 10.10.0.0/16)
  --fw-syslog IP             rôle wazuh : accepte le syslog du pare-feu OPNsense
  --site-name FQDN           rôle web : nom du site (défaut : www.acme.local)
  --web-root CHEMIN          rôle web : racine du site (défaut : /var/www/html)
  --deploy-vhost             rôle web : déploie le vhost durci (désactive le site "default")
  --disable-ipv6             désactive IPv6 (si non utilisé dans le plan d'adressage)
  -y, --yes                  pas de confirmation interactive
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)           ROLE="$2"; shift 2 ;;
        --steps)          STEPS_ARG="$2"; shift 2 ;;
        --admin)          ADMIN_USER="$2"; shift 2 ;;
        --admin-pubkey)   ADMIN_PUBKEY="$2"; shift 2 ;;
        --admin-net)      ADMIN_NET="$2"; shift 2 ;;
        --ssh-port)       SSH_PORT="$2"; shift 2 ;;
        --ntp)            NTP_SERVERS="$2"; shift 2 ;;
        --wazuh-manager)  WAZUH_MANAGER="$2"; shift 2 ;;
        --wazuh-group)    WAZUH_GROUP="$2"; shift 2 ;;
        --wazuh-version)  WAZUH_VERSION="$2"; shift 2 ;;
        --agent-nets)     AGENT_NETS="$2"; shift 2 ;;
        --fw-syslog)      FW_SYSLOG="$2"; shift 2 ;;
        --site-name)      SITE_NAME="$2"; shift 2 ;;
        --web-root)       WEB_ROOT="$2"; shift 2 ;;
        --deploy-vhost)   DEPLOY_VHOST=1; shift ;;
        --disable-ipv6)   DISABLE_IPV6=1; shift ;;
        -y|--yes)         ASSUME_YES=1; shift ;;
        -h|--help)        usage ;;
        *) echo "Option inconnue : $1 (voir --help)"; exit 1 ;;
    esac
done

# -----------------------------------------------------------------------------
#  Vérifications préalables
# -----------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "À lancer en root (sudo)."; exit 1; }
[[ "$ROLE" =~ ^(base|web|wazuh)$ ]] || { echo "Rôle invalide : $ROLE"; exit 1; }
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then echo "Ubuntu requis (détecté : ${ID:-?})"; exit 1; fi
case "${VERSION_ID:-}" in 22.04|24.04) ;; *) echo "Attention : testé pour 22.04 / 24.04 (détecté : ${VERSION_ID:-?})" ;; esac

# Compte admin : par défaut, l'utilisateur existant qui a lancé sudo (pas de création de compte)
if [[ -z "$ADMIN_USER" ]]; then
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then ADMIN_USER="$SUDO_USER"
    else echo "Lancé en root direct : précisez le compte admin avec --admin NOM (ou lancez via sudo depuis votre compte)."; exit 1; fi
fi

# Clé publique passée sous forme de fichier
if [[ -n "$ADMIN_PUBKEY" && -f "$ADMIN_PUBKEY" ]]; then ADMIN_PUBKEY="$(cat "$ADMIN_PUBKEY")"; fi

# Étapes par défaut selon le rôle
if [[ -z "$STEPS_ARG" ]]; then
    case "$ROLE" in
        base)  STEPS_ARG="0-11,16" ;;
        web)   STEPS_ARG="0-12,16" ;;
        wazuh) STEPS_ARG="0-11,13,16" ;;
    esac
    [[ -n "$WAZUH_MANAGER" && "$ROLE" != "wazuh" ]] && STEPS_ARG="$STEPS_ARG,14"
fi
STEPS=()
IFS=',' read -ra _parts <<< "$STEPS_ARG"
for p in "${_parts[@]}"; do
    if [[ "$p" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        for ((i=BASH_REMATCH[1]; i<=BASH_REMATCH[2]; i++)); do STEPS+=("$i"); done
    elif [[ "$p" =~ ^[0-9]+$ ]]; then STEPS+=("$p")
    else echo "Étapes invalides : $STEPS_ARG"; exit 1; fi
done

STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="/root/acme-hardening/$STAMP"
mkdir -p "$REPORT_DIR"
chmod 700 /root/acme-hardening
LOG="$REPORT_DIR/hardening.log"
WARN_FILE="$REPORT_DIR/avertissements.txt"
: > "$WARN_FILE"
exec > >(tee -a "$LOG") 2>&1

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
HAS_DOCKER=0; command -v docker >/dev/null 2>&1 && HAS_DOCKER=1
HAS_IPV6=0;   [[ -s /proc/net/if_inet6 && $DISABLE_IPV6 -eq 0 ]] && HAS_IPV6=1

# -----------------------------------------------------------------------------
#  Fonctions utilitaires
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then C_CYAN=$'\e[36m'; C_GREEN=$'\e[32m'; C_YEL=$'\e[33m'; C_RED=$'\e[31m'; C_RST=$'\e[0m'
else C_CYAN=""; C_GREEN=""; C_YEL=""; C_RED=""; C_RST=""; fi
section() { echo; echo "${C_CYAN}===== Étape $1 : $2 =====${C_RST}"; }
ok()      { echo "  ${C_GREEN}[OK]${C_RST} $*"; }
info()    { echo "  ${C_YEL}[i]${C_RST}  $*"; }
warn()    { echo "  ${C_RED}[!]${C_RST}  $*"; echo "$*" >> "$WARN_FILE"; }

apt_install() { apt-get install "${APT_OPTS[@]}" --no-install-recommends "$@" >/dev/null; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

# Fixe "CLE VALEUR" (séparateur espace) ou "CLE=VALEUR" dans un fichier de conf
set_kv() {   # set_kv fichier clé valeur [séparateur]  (ne touche que les lignes actives, sinon ajoute)
    local f="$1" k="$2" v="$3" sep="${4:- }" re
    re="${sep// /}"; [[ -z "$re" ]] && re="[[:space:]]"
    touch "$f"
    if grep -Eq "^[[:space:]]*${k}[[:space:]]*${re}" "$f"; then
        sed -ri "s|^[[:space:]]*${k}[[:space:]]*${re}.*|${k}${sep}${v}|" "$f"
    else
        echo "${k}${sep}${v}" >> "$f"
    fi
}

# Une IP appartient-elle à l'un des réseaux (liste séparée par des virgules) ?
ip_in_nets() {
    python3 - "$1" "$2" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
nets = [n.strip() for n in sys.argv[2].split(',') if n.strip()]
sys.exit(0 if any(ip in ipaddress.ip_network(n, strict=False) for n in nets) else 1)
PY
}

# IP des sessions SSH actuellement établies (pour ne pas se couper soi-même)
current_ssh_peers() {
    local port
    port="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
    ss -Htn state established "( sport = :${port:-22} )" 2>/dev/null \
        | awk '{print $NF}' | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff://' | sort -u
}

lynis_index() { grep -E '^hardening_index=' "$1" 2>/dev/null | cut -d= -f2 || true; }

FAILED=()
run_step() {   # run_step numéro fonction "titre"
    local n="$1" fn="$2" title="$3" rc
    [[ " ${STEPS[*]} " == *" $n "* ]] || return 0
    section "$n" "$title"
    ( set -Eeuo pipefail
      trap 'echo "  ${C_RED}[ERREUR]${C_RST} ligne $LINENO : $BASH_COMMAND" >&2' ERR
      "$fn" )
    rc=$?
    if [[ $rc -ne 0 ]]; then FAILED+=("Étape $n - $title (code $rc)"); fi
}

# =============================================================================
#  ÉTAPE 0 - Audit initial
# =============================================================================
step_00_audit_initial() {
    apt-get update -q >/dev/null
    pkg_installed lynis || apt_install lynis
    info "Audit Lynis en cours (1 à 3 minutes)..."
    lynis audit system --quiet --no-colors \
        --logfile "$REPORT_DIR/lynis-avant.log" --report-file "$REPORT_DIR/lynis-avant.dat" >/dev/null || true
    ok "Indice de durcissement Lynis AVANT : $(lynis_index "$REPORT_DIR/lynis-avant.dat")/100"
    ss -tulpn > "$REPORT_DIR/ports-ecoute-avant.txt"
    systemctl list-unit-files --state=enabled --type=service > "$REPORT_DIR/services-avant.txt"
    ok "Ports en écoute et services actifs sauvegardés (preuve de l'état initial)"
}

# =============================================================================
#  ÉTAPE 1 - Sauvegarde et prérequis
# =============================================================================
step_01_sauvegarde() {
    tar -czpf "$REPORT_DIR/etc-avant.tar.gz" -C / etc 2>/dev/null
    chmod 600 "$REPORT_DIR/etc-avant.tar.gz"
    ok "Copie de /etc : $REPORT_DIR/etc-avant.tar.gz (restauration : tar -xzpf ... -C /)"
    apt-get update -q >/dev/null
    apt_install ca-certificates curl gnupg python3 iproute2 openssl
    ok "Paquets prérequis présents"
}

# =============================================================================
#  ÉTAPE 2 - Mises à jour
# =============================================================================
step_02_mises_a_jour() {
    apt-get update -q >/dev/null
    apt-get "${APT_OPTS[@]}" full-upgrade >/dev/null
    apt-get "${APT_OPTS[@]}" autoremove --purge >/dev/null
    ok "Système à jour (full-upgrade + autoremove)"

    apt_install unattended-upgrades needrestart
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    cat > /etc/apt/apt.conf.d/52unattended-upgrades-acme <<'EOF'
// ACME : seules les mises à jour de SÉCURITÉ Ubuntu sont installées automatiquement
// (les dépôts tiers comme Wazuh restent manuels pour garder agent <= manager).
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF
    systemctl enable --now unattended-upgrades >/dev/null 2>&1
    ok "Mises à jour de sécurité automatiques activées (sans redémarrage automatique)"
    [[ -f /var/run/reboot-required ]] && warn "Un redémarrage est requis pour finaliser les mises à jour (noyau)"
    return 0
}

# =============================================================================
#  ÉTAPE 3 - Comptes et authentification
# =============================================================================
step_03_comptes() {
    # --- Qualité des mots de passe (équivalent Linux de la Default Domain Policy)
    apt_install libpam-pwquality
    mkdir -p /etc/security/pwquality.conf.d
    cat > /etc/security/pwquality.conf.d/60-acme.conf <<'EOF'
# ACME - aligné sur la politique AD (12 caractères min., 3 classes)
minlen = 12
minclass = 3
maxrepeat = 3
maxsequence = 4
dictcheck = 1
usercheck = 1
difok = 4
retry = 3
enforce_for_root
EOF
    ok "pwquality : 12 caractères, 3 classes, dictionnaire, appliqué aussi à root"

    # --- Verrouillage après échecs (pam_faillock, méthode pam-auth-update recommandée par le CIS Ubuntu)
    cat > /etc/security/faillock.conf <<'EOF'
# ACME - 5 échecs en 15 min => verrouillage 15 min (root exclu : il est déjà verrouillé)
deny = 5
fail_interval = 900
unlock_time = 900
audit
silent
EOF
    cat > /usr/share/pam-configs/faillock <<'EOF'
Name: ACME - pam_faillock (verrouillage apres echecs)
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
Account-Type: Additional
Account:
	required	pam_faillock.so
EOF
    cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: ACME - pam_faillock (preauth)
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
EOF
    # --- Historique des mots de passe (24, comme l'AD) - placé après pwquality (priorité 1024)
    cat > /usr/share/pam-configs/pwhistory <<'EOF'
Name: ACME - pam_pwhistory (24 derniers mots de passe)
Default: no
Priority: 1023
Password-Type: Primary
Password:
	requisite	pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
EOF
    pam-auth-update --package --enable faillock faillock_notify pwhistory
    grep -q pam_faillock /etc/pam.d/common-auth && ok "pam_faillock actif (déverrouiller : faillock --user NOM --reset)"
    grep -q pam_pwhistory /etc/pam.d/common-password && ok "Historique : 24 mots de passe mémorisés"

    # --- Durées de validité (login.defs) et masque par défaut
    set_kv /etc/login.defs PASS_MAX_DAYS 365
    set_kv /etc/login.defs PASS_MIN_DAYS 1
    set_kv /etc/login.defs PASS_WARN_AGE 14
    set_kv /etc/login.defs UMASK 027
    set_kv /etc/login.defs ENCRYPT_METHOD YESCRYPT
    set_kv /etc/login.defs LOG_OK_LOGINS yes
    set_kv /etc/adduser.conf DIR_MODE 0750 "="
    useradd -D -f 30
    while IFS=: read -r u _ uid _ _ _ shell; do
        if [[ $uid -ge 1000 && $uid -lt 65534 && "$shell" != */nologin && "$shell" != */false ]]; then
            chage --maxdays 365 --mindays 1 --warndays 14 "$u"
        fi
    done < /etc/passwd
    ok "Expiration 365 j, délai mini 1 j, alerte 14 j, comptes inactifs désactivés après 30 j"

    # --- Groupe des comptes autorisés en SSH
    getent group ssh-users >/dev/null || groupadd ssh-users
    # tous les membres actuels de sudo + l'utilisateur qui lance le script (anti-lockout)
    for u in $(getent group sudo | cut -d: -f4 | tr ',' ' ') ${SUDO_USER:-}; do
        [[ -n "$u" && "$u" != "root" ]] && usermod -aG ssh-users "$u"
    done

    # --- Compte d'administration nominatif
    if ! id "$ADMIN_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -c "Administrateur nominatif ACME" -G sudo,ssh-users "$ADMIN_USER"
        ok "Compte $ADMIN_USER créé (membre de sudo et ssh-users)"
        if [[ -t 0 ]]; then
            local essai
            for essai in 1 2 3; do
                echo "  Mot de passe pour $ADMIN_USER (12 car. min., sert pour sudo) :"
                if passwd "$ADMIN_USER" </dev/tty; then break; fi
            done
        else
            passwd -l "$ADMIN_USER" >/dev/null
            warn "$ADMIN_USER créé SANS mot de passe (session non interactive) : définissez-le avec passwd"
        fi
    else
        usermod -aG sudo,ssh-users "$ADMIN_USER"
        info "Compte $ADMIN_USER déjà présent (ajouté à sudo/ssh-users)"
    fi
    if [[ -n "$ADMIN_PUBKEY" ]]; then
        local home; home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
        install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
        touch "$home/.ssh/authorized_keys"
        grep -qF "$ADMIN_PUBKEY" "$home/.ssh/authorized_keys" || echo "$ADMIN_PUBKEY" >> "$home/.ssh/authorized_keys"
        chown "$ADMIN_USER:$ADMIN_USER" "$home/.ssh/authorized_keys"; chmod 600 "$home/.ssh/authorized_keys"
        ok "Clé publique SSH installée pour $ADMIN_USER"
    fi

    # --- root : mot de passe verrouillé, su réservé à un groupe vide (on passe par sudo, tracé)
    passwd -l root >/dev/null
    getent group sugroup >/dev/null || groupadd sugroup
    if ! grep -Eq '^auth\s+required\s+pam_wheel\.so' /etc/pam.d/su; then
        sed -i '0,/^#\s*auth\s\+required\s\+pam_wheel.so/s//auth       required   pam_wheel.so use_uid group=sugroup\n&/' /etc/pam.d/su
        grep -Eq '^auth\s+required\s+pam_wheel\.so' /etc/pam.d/su || \
            echo 'auth       required   pam_wheel.so use_uid group=sugroup' >> /etc/pam.d/su
    fi
    ok "root verrouillé, commande su interdite (groupe sugroup vide) : utiliser sudo"

    # --- sudo : journal dédié, pseudo-terminal, délai court
    cat > /etc/sudoers.d/50-acme-hardening <<'EOF'
# ACME - durcissement sudo
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=5
Defaults passwd_tries=3
Defaults !visiblepw
Defaults env_reset
EOF
    chmod 440 /etc/sudoers.d/50-acme-hardening
    visudo -cq || { rm -f /etc/sudoers.d/50-acme-hardening; echo "sudoers invalide"; return 1; }
    ok "sudo : journal /var/log/sudo.log, use_pty, délai 5 min"
    if grep -rqs 'NOPASSWD' /etc/sudoers /etc/sudoers.d/; then
        warn "Règle(s) sudo NOPASSWD trouvée(s) : $(grep -rls NOPASSWD /etc/sudoers.d/ /etc/sudoers | tr '\n' ' ') - à supprimer si non justifiée"
    fi

    # --- Déconnexion des shells inactifs et umask
    cat > /etc/profile.d/99-acme-hardening.sh <<'EOF'
# ACME - shells inactifs fermés après 15 min, fichiers créés non lisibles par "autres"
if [ "${TMOUT:-}" != "900" ]; then TMOUT=900; readonly TMOUT; export TMOUT; fi
umask 027
EOF
    ok "TMOUT=900 s et umask 027 pour les sessions interactives"
    systemctl mask ctrl-alt-del.target >/dev/null 2>&1
    ok "Ctrl+Alt+Suppr désactivé sur la console"
}

# =============================================================================
#  ÉTAPE 4 - SSH
# =============================================================================
step_04_ssh() {
    getent group ssh-users >/dev/null || groupadd ssh-users
    for u in $(getent group sudo | cut -d: -f4 | tr ',' ' ') ${SUDO_USER:-}; do
        [[ -n "$u" && "$u" != "root" ]] && usermod -aG ssh-users "$u"
    done

    # Clés d'hôte : on ne garde que Ed25519 et RSA 3072+
    ssh-keygen -A >/dev/null 2>&1
    if [[ -f /etc/ssh/ssh_host_rsa_key ]] && \
       [[ $(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key | awk '{print $1}') -lt 3072 ]]; then
        rm -f /etc/ssh/ssh_host_rsa_key{,.pub}
        ssh-keygen -q -t rsa -b 4096 -N '' -f /etc/ssh/ssh_host_rsa_key
        ok "Clé d'hôte RSA régénérée en 4096 bits"
    fi
    # Groupes Diffie-Hellman < 3072 bits supprimés
    if awk '$5 < 3071' /etc/ssh/moduli | grep -qv '^#'; then
        cp /etc/ssh/moduli "$REPORT_DIR/moduli.bak"
        awk '$1 ~ /^#/ || $5 >= 3071' "$REPORT_DIR/moduli.bak" > /etc/ssh/moduli
        ok "Moduli DH < 3072 bits supprimés"
    fi

    if [[ -z "$(getent group ssh-users | cut -d: -f4)" ]]; then
        echo "Le groupe ssh-users est vide : personne ne pourrait se connecter. Lancez d'abord l'étape 3 (compte $ADMIN_USER)."
        return 1
    fi
    [[ -z "${SUDO_USER:-}" ]] && warn "Script lancé en root direct : la connexion SSH en root sera INTERDITE, utilisez $ADMIN_USER"

    # Authentification par mot de passe désactivée seulement si TOUS les comptes autorisés ont une clé
    local pwauth="no" sans_cle=()
    for u in $(getent group ssh-users | cut -d: -f4 | tr ',' ' '); do
        local h; h="$(getent passwd "$u" | cut -d: -f6)"
        [[ -s "$h/.ssh/authorized_keys" ]] || sans_cle+=("$u")
    done
    if [[ ${#sans_cle[@]} -gt 0 ]]; then
        pwauth="yes"
        warn "Mot de passe SSH CONSERVÉ : comptes sans clé -> ${sans_cle[*]}. Déployez une clé (ssh-copy-id) puis relancez --steps 4"
    fi

    cat > /etc/ssh/sshd_config.d/00-acme-hardening.conf <<EOF
# ACME - durcissement OpenSSH (prioritaire : la première valeur lue l'emporte)
Port ${SSH_PORT}
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Algorithmes (ANSSI / Mozilla "modern")
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
RekeyLimit 512M 1h

# Authentification
PermitRootLogin no
AllowGroups ssh-users
PubkeyAuthentication yes
PasswordAuthentication ${pwauth}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30
StrictModes yes

# Sessions et fonctionnalités inutiles
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
Compression no
UseDNS no

# Traçabilité (VERBOSE = empreinte de la clé utilisée, exploitable par Wazuh)
LogLevel VERBOSE
SyslogFacility AUTH
PrintLastLog yes
Banner /etc/issue.net
DebianBanner no
EOF
    chmod 600 /etc/ssh/sshd_config.d/00-acme-hardening.conf
    chmod 600 /etc/ssh/sshd_config

    [[ -s /etc/issue.net ]] || echo "Accès réservé aux personnes autorisées." > /etc/issue.net
    if ! sshd -t; then
        mv /etc/ssh/sshd_config.d/00-acme-hardening.conf "$REPORT_DIR/sshd-rejete.conf"
        echo "Configuration SSH invalide : retirée (copie dans $REPORT_DIR)"; return 1
    fi

    # Si le port change et qu'UFW est déjà actif, on ouvre le nouveau port AVANT de redémarrer
    if ufw status 2>/dev/null | grep -q 'Status: active'; then
        for net in ${ADMIN_NET//,/ }; do ufw limit proto tcp from "$net" to any port "$SSH_PORT" comment 'SSH admin' >/dev/null; done
    fi
    if systemctl is-active --quiet ssh.socket; then      # Ubuntu 24.04 : activation par socket
        systemctl daemon-reload
        systemctl restart ssh.socket
        systemctl restart ssh.service 2>/dev/null || true
    else
        systemctl restart ssh
    fi
    ok "SSH durci (root interdit, groupe ssh-users, algorithmes modernes, mot de passe : ${pwauth})"
    info "Testez une NOUVELLE connexion avant de fermer la session actuelle : ssh -p ${SSH_PORT} ${ADMIN_USER}@$(hostname -I | awk '{print $1}')"
}

# =============================================================================
#  ÉTAPE 5 - Pare-feu
# =============================================================================
step_05_parefeu() {
    apt_install ufw
    if [[ $DISABLE_IPV6 -eq 1 ]]; then set_kv /etc/default/ufw IPV6 no "="; fi
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    [[ $HAS_DOCKER -eq 0 ]] && ufw default deny routed >/dev/null

    # SSH : uniquement depuis le réseau d'administration, avec limitation de débit
    for net in ${ADMIN_NET//,/ }; do
        ufw limit proto tcp from "$net" to any port "$SSH_PORT" comment 'SSH admin' >/dev/null
    done
    # Anti-lockout : session(s) SSH en cours hors du réseau d'admin
    local peer
    for peer in $(current_ssh_peers); do
        if ! ip_in_nets "$peer" "$ADMIN_NET"; then
            ufw allow proto tcp from "$peer" to any port "$SSH_PORT" comment 'SSH session en cours - TEMPORAIRE' >/dev/null
            warn "Session SSH depuis $peer hors de $ADMIN_NET : autorisée temporairement. À supprimer : ufw status numbered puis ufw delete N"
        fi
    done

    # Règles SSH ouvertes à tous (ex. "ufw allow OpenSSH" fait à l'installation) : supprimées
    for r in OpenSSH 22/tcp 22 "${SSH_PORT}/tcp" "$SSH_PORT"; do ufw --force delete allow "$r" >/dev/null 2>&1 || true; done

    case "$ROLE" in
        web)
            ufw allow 80/tcp  comment 'HTTP (redirection HTTPS)' >/dev/null
            ufw allow 443/tcp comment 'HTTPS site vitrine' >/dev/null
            ok "Rôle web : 80 et 443 ouverts" ;;
        wazuh)
            for net in ${AGENT_NETS//,/ }; do
                ufw allow proto tcp from "$net" to any port 1514,1515 comment 'Wazuh agents (evenements + enrolement)' >/dev/null
            done
            for net in ${ADMIN_NET//,/ }; do
                ufw allow proto tcp from "$net" to any port 443   comment 'Wazuh dashboard' >/dev/null
                ufw allow proto tcp from "$net" to any port 55000 comment 'Wazuh API' >/dev/null
            done
            [[ -n "$FW_SYSLOG" ]] && ufw allow proto udp from "$FW_SYSLOG" to any port 514 comment 'Syslog ACME-FW01' >/dev/null
            ok "Rôle wazuh : 1514-1515 depuis $AGENT_NETS ; 443 et 55000 depuis $ADMIN_NET ; indexer 9200 non exposé" ;;
    esac

    ufw logging low >/dev/null
    ufw --force enable >/dev/null
    ufw status verbose > "$REPORT_DIR/ufw-regles.txt"
    ok "UFW actif : entrant refusé par défaut (règles dans $REPORT_DIR/ufw-regles.txt)"
}

# =============================================================================
#  ÉTAPE 6 - Noyau
# =============================================================================
step_06_noyau() {
    local f=/etc/sysctl.d/60-acme-hardening.conf
    local params=(
        # Fuites d'informations noyau / exploitation
        "kernel.kptr_restrict=2" "kernel.dmesg_restrict=1" "kernel.randomize_va_space=2"
        "kernel.yama.ptrace_scope=1" "kernel.sysrq=0" "kernel.unprivileged_bpf_disabled=1"
        "net.core.bpf_jit_harden=2" "dev.tty.ldisc_autoload=0" "vm.unprivileged_userfaultfd=0"
        "fs.protected_hardlinks=1" "fs.protected_symlinks=1" "fs.protected_fifos=2"
        "fs.protected_regular=2" "fs.suid_dumpable=0"
        # Réseau IPv4
        "net.ipv4.conf.all.accept_redirects=0" "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0" "net.ipv4.conf.default.secure_redirects=0"
        "net.ipv4.conf.all.send_redirects=0"   "net.ipv4.conf.default.send_redirects=0"
        "net.ipv4.conf.all.accept_source_route=0" "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"
        "net.ipv4.conf.all.log_martians=1" "net.ipv4.conf.default.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1" "net.ipv4.icmp_ignore_bogus_error_responses=1"
        "net.ipv4.tcp_syncookies=1" "net.ipv4.tcp_rfc1337=1"
        # Réseau IPv6 (serveurs en adressage statique)
        "net.ipv6.conf.all.accept_redirects=0" "net.ipv6.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_source_route=0" "net.ipv6.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.accept_ra=0" "net.ipv6.conf.default.accept_ra=0"
    )
    # Un serveur n'est pas un routeur (sauf hôte Docker)
    [[ $HAS_DOCKER -eq 0 ]] && params+=("net.ipv4.ip_forward=0" "net.ipv6.conf.all.forwarding=0")
    [[ $DISABLE_IPV6 -eq 1 ]] && params+=("net.ipv6.conf.all.disable_ipv6=1" "net.ipv6.conf.default.disable_ipv6=1")

    echo "# ACME - durcissement noyau (généré par hardening-acme-ubuntu.sh v$VERSION)" > "$f"
    local p k ignores=()
    for p in "${params[@]}"; do
        k="${p%%=*}"
        if [[ -e "/proc/sys/${k//.//}" ]]; then echo "$p" >> "$f"; else ignores+=("$k"); fi
    done
    sysctl -q --system >/dev/null
    ok "$(grep -c '=' "$f") paramètres sysctl appliqués (redirections ICMP, routage source, ASLR, ptrace, BPF...)"
    [[ ${#ignores[@]} -gt 0 ]] && info "Ignorés (absents de ce noyau) : ${ignores[*]}"

    # Modules noyau inutiles sur un serveur virtuel (squashfs conservé : requis par snap)
    local mods=(cramfs freevxfs jffs2 hfs hfsplus udf usb-storage firewire-core thunderbolt dccp sctp rds tipc bluetooth)
    : > /etc/modprobe.d/60-acme-hardening.conf
    for m in "${mods[@]}"; do
        printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" >> /etc/modprobe.d/60-acme-hardening.conf
        modprobe -r "$m" 2>/dev/null || true
    done
    ok "Modules désactivés : ${mods[*]}"

    # Pas de core dumps (peuvent contenir mots de passe / clés en mémoire)
    echo '* hard core 0' > /etc/security/limits.d/60-acme-nocore.conf
    mkdir -p /etc/systemd/coredump.conf.d
    printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/60-acme.conf
    ok "Core dumps désactivés"
}

# =============================================================================
#  ÉTAPE 7 - Systèmes de fichiers et permissions
# =============================================================================
step_07_fichiers() {
    # /tmp en tmpfs noexec,nosuid,nodev (sauf serveur Wazuh : l'indexer OpenSearch exécute du code natif depuis /tmp)
    if [[ "$ROLE" != "wazuh" ]]; then
        cat > /etc/systemd/system/tmp.mount <<'EOF'
[Unit]
Description=Temporary Directory /tmp (ACME : noexec,nosuid,nodev)
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=25%%

[Install]
WantedBy=local-fs.target
EOF
        systemctl daemon-reload
        systemctl enable tmp.mount >/dev/null 2>&1
        # apt/dpkg ont parfois besoin d'exécuter depuis /tmp : remontage temporaire
        cat > /etc/apt/apt.conf.d/50acme-tmp-exec <<'EOF'
DPkg::Pre-Invoke  {"mountpoint -q /tmp && mount -o remount,exec /tmp || true";};
DPkg::Post-Invoke {"mountpoint -q /tmp && mount -o remount,noexec /tmp || true";};
EOF
        ok "/tmp en tmpfs noexec,nosuid,nodev (effectif au prochain redémarrage)"
    else
        info "Rôle wazuh : /tmp laissé tel quel (wazuh-indexer a besoin d'exécuter dans /tmp)"
    fi

    if ! grep -Eq '^\S+\s+/dev/shm\s' /etc/fstab; then
        echo 'tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab
    fi
    mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null || true
    ok "/dev/shm monté noexec,nosuid,nodev"

    # Fichiers sensibles
    chmod 600 /etc/crontab
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
    rm -f /etc/cron.deny /etc/at.deny
    echo root > /etc/cron.allow; chmod 600 /etc/cron.allow
    echo root > /etc/at.allow;   chmod 600 /etc/at.allow
    chmod 644 /etc/passwd /etc/group
    chmod 640 /etc/shadow /etc/gshadow; chown root:shadow /etc/shadow /etc/gshadow
    [[ -f /boot/grub/grub.cfg ]] && chmod 400 /boot/grub/grub.cfg
    ok "Permissions : crontab, cron.*, cron.allow/at.allow (root seul), shadow, grub.cfg"

    # Répertoires personnels non lisibles par les autres
    while IFS=: read -r u _ uid _ _ home _; do
        [[ $uid -ge 1000 && $uid -lt 65534 && -d "$home" ]] && chmod 750 "$home"
    done < /etc/passwd
    ok "Répertoires personnels en 750"

    # Rapports (on ne modifie pas, on documente)
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort > "$REPORT_DIR/binaires-suid-sgid.txt"
    find / -xdev -type f -perm -0002 2>/dev/null | grep -Ev '^/(proc|sys)/' > "$REPORT_DIR/fichiers-world-writable.txt" || true
    find / -xdev \( -nouser -o -nogroup \) 2>/dev/null > "$REPORT_DIR/fichiers-sans-proprietaire.txt" || true
    ok "Rapports : $(wc -l < "$REPORT_DIR/binaires-suid-sgid.txt") binaires SUID/SGID, $(wc -l < "$REPORT_DIR/fichiers-world-writable.txt") fichiers modifiables par tous"
}

# =============================================================================
#  ÉTAPE 8 - Services, paquets, bannières
# =============================================================================
step_08_services() {
    local purge=() p
    for p in telnet inetutils-telnet rsh-client rsh-redone-client talk ntalk nis ftp tnftp xinetd \
             avahi-daemon cups cups-daemon popularity-contest; do
        pkg_installed "$p" && purge+=("$p")
    done
    if [[ ${#purge[@]} -gt 0 ]]; then
        apt-get "${APT_OPTS[@]}" purge "${purge[@]}" >/dev/null
        ok "Paquets supprimés : ${purge[*]}"
    else info "Aucun paquet obsolète/dangereux à supprimer"; fi

    local s
    for s in rpcbind rpcbind.socket ModemManager bluetooth apport whoopsie motd-news.timer; do
        if systemctl list-unit-files --no-legend "${s}*" 2>/dev/null | grep -q .; then
            systemctl disable --now "$s" >/dev/null 2>&1 && ok "Service $s désactivé"
        fi
    done
    [[ -f /etc/default/motd-news ]] && set_kv /etc/default/motd-news ENABLED 0 "="
    [[ -f /etc/default/apport ]]    && set_kv /etc/default/apport enabled 0 "="

    # Synchronisation horaire (corrélation des journaux dans Wazuh)
    if [[ -n "$NTP_SERVERS" ]]; then
        mkdir -p /etc/systemd/timesyncd.conf.d
        printf '[Time]\nNTP=%s\nFallbackNTP=\n' "$NTP_SERVERS" > /etc/systemd/timesyncd.conf.d/60-acme.conf
        systemctl restart systemd-timesyncd 2>/dev/null || true
        ok "NTP interne : $NTP_SERVERS"
    else
        info "NTP : serveurs Ubuntu par défaut (--ntp IP pour utiliser OPNsense ou le DC)"
    fi
    timedatectl set-timezone Europe/Paris

    # Bannières légales
    local banniere
    banniere=$(cat <<'EOF'
***************************************************************************
  Système d'information ACME - accès réservé aux personnes autorisées.
  Toutes les connexions sont journalisées et supervisées. Tout accès ou
  tentative d'accès non autorisé expose son auteur à des poursuites
  (articles 323-1 et suivants du Code pénal).
***************************************************************************
EOF
)
    echo "$banniere" > /etc/issue
    echo "$banniere" > /etc/issue.net
    chmod 644 /etc/issue /etc/issue.net
    chmod -x /etc/update-motd.d/10-help-text /etc/update-motd.d/50-motd-news 2>/dev/null || true
    ok "Bannières légales (console + SSH), motd publicitaire désactivé"

    ss -tulpn > "$REPORT_DIR/ports-ecoute-apres.txt"
    info "Ports encore en écoute : voir $REPORT_DIR/ports-ecoute-apres.txt"
}

# =============================================================================
#  ÉTAPE 9 - Journalisation et audit
# =============================================================================
step_09_journaux() {
    # journald persistant
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/60-acme.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
ForwardToSyslog=yes
EOF
    systemctl restart systemd-journald
    ok "journald persistant (500 Mo max)"

    apt_install auditd audispd-plugins
    local ac=/etc/audit/auditd.conf
    set_kv "$ac" max_log_file 50 " = "
    set_kv "$ac" num_logs 10 " = "
    set_kv "$ac" max_log_file_action ROTATE " = "
    set_kv "$ac" space_left_action SYSLOG " = "
    set_kv "$ac" admin_space_left_action SUSPEND " = "
    set_kv "$ac" disk_full_action SUSPEND " = "

    # Audit dès le démarrage
    if ! grep -q 'audit=1' /etc/default/grub; then
        sed -ri 's/^(GRUB_CMDLINE_LINUX=")(.*)"/\1\2 audit=1 audit_backlog_limit=8192"/' /etc/default/grub
        sed -ri 's/^(GRUB_CMDLINE_LINUX=") /\1/' /etc/default/grub
        update-grub >/dev/null 2>&1
        ok "audit=1 ajouté aux paramètres de démarrage"
    fi

    local r=/etc/audit/rules.d/60-acme-hardening.rules
    cat > "$r" <<'EOF'
## ACME - règles d'audit (inspirées du CIS Ubuntu Linux Benchmark, section 6.3)
-b 8192
--backlog_wait_time 60000
-f 1

## Date et heure
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## Comptes et groupes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam

## Réseau et identité de la machine
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale

## AppArmor
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

## Connexions et sessions
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

## Élévation de privilèges
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation

## Modifications de permissions par les utilisateurs
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

## Accès refusés
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

## Montages et suppressions
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

## Modules noyau
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /usr/bin/kmod -p x -k modules

## Configuration sensible
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/audit/ -p wa -k auditconfig
-w /etc/systemd/ -p wa -k systemd
EOF
    # Commandes privilégiées (SUID/SGID) détectées sur CETTE machine
    {
        echo "## Commandes privilégiées (générées automatiquement)"
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort | while read -r b; do
            echo "-a always,exit -F path=$b -F perm=x -F auid>=1000 -F auid!=unset -k privileged"
        done
        case "$ROLE" in
            web)   echo "-w /etc/nginx/ -p wa -k nginx-conf" ;;
            wazuh) echo "-w /var/ossec/etc/ -p wa -k wazuh-conf" ;;
        esac
    } >> "$r"
    # Règles immuables (modification = redémarrage) : un attaquant root ne peut pas couper l'audit discrètement
    echo '-e 2' > /etc/audit/rules.d/99-zz-acme-immutable.rules

    systemctl enable auditd >/dev/null 2>&1
    if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
        warn "Règles d'audit déjà immuables : les nouvelles règles seront chargées au prochain redémarrage"
    else
        augenrules --load >/dev/null 2>&1 || true
        systemctl restart auditd 2>/dev/null || service auditd restart >/dev/null 2>&1 || true
    fi
    ok "auditd : $(grep -c '^-[aw]' "$r") règles (identités, sudo, permissions, accès refusés, modules, SUID...)"
    info "Consultation : ausearch -k identity -i  |  aureport --summary"

    # Permissions des journaux
    find /var/log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
    ok "Journaux de /var/log non lisibles par les autres utilisateurs"
}

# =============================================================================
#  ÉTAPE 10 - Fail2ban
# =============================================================================
step_10_fail2ban() {
    apt_install fail2ban python3-systemd
    cat > /etc/fail2ban/jail.d/60-acme.local <<EOF
# ACME - bannissement progressif (1 h, doublé à chaque récidive)
[DEFAULT]
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 5
banaction = ufw
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
mode = aggressive
EOF
    if [[ "$ROLE" == "web" ]]; then
        cat >> /etc/fail2ban/jail.d/60-acme.local <<'EOF'

[nginx-http-auth]
enabled = true
logpath = /var/log/nginx/*error.log

[nginx-botsearch]
enabled = true
logpath = /var/log/nginx/*error.log

[nginx-limit-req]
enabled = true
logpath = /var/log/nginx/*error.log
maxretry = 10
EOF
    fi
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    sleep 2
    ok "Fail2ban actif : $(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{print $2}' | xargs)"
    info "Test (depuis une autre machine) : 6 échecs SSH -> IP bannie ; fail2ban-client status sshd"
}

# =============================================================================
#  ÉTAPE 11 - AppArmor
# =============================================================================
step_11_apparmor() {
    apt_install apparmor apparmor-utils
    systemctl enable --now apparmor >/dev/null 2>&1
    aa-status > "$REPORT_DIR/apparmor-status.txt" 2>&1 || true
    ok "AppArmor actif : $(aa-status --enforced 2>/dev/null || echo '?') profils en mode enforce"
    local complain; complain="$(aa-status --complaining 2>/dev/null || echo 0)"
    [[ "$complain" != "0" ]] && info "$complain profil(s) en mode complain (détail : $REPORT_DIR/apparmor-status.txt)"
    return 0
}

# =============================================================================
#  ÉTAPE 12 - Rôle web : nginx
# =============================================================================
comment_nginx_directive() {   # neutralise une directive déjà présente dans nginx.conf (évite "duplicate")
    sed -ri "s/^([[:space:]]*)($1[[:space:]].*)$/\1# \2  # désactivé par ACME (cf. conf.d\/00-acme-hardening.conf)/" /etc/nginx/nginx.conf
}

step_12_nginx() {
    pkg_installed nginx || apt_install nginx
    local bak="$REPORT_DIR/nginx-avant"
    cp -a /etc/nginx "$bak"
    local ver; ver="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
    info "nginx $ver"

    # --- Paramètres globaux (contexte http)
    for d in server_tokens ssl_protocols ssl_prefer_server_ciphers ssl_ciphers ssl_session_cache \
             ssl_session_timeout ssl_session_tickets keepalive_timeout client_max_body_size; do
        comment_nginx_directive "$d"
    done
    cat > /etc/nginx/conf.d/00-acme-hardening.conf <<'EOF'
# ACME - durcissement global nginx
server_tokens off;                       # masque la version (en-tête Server + pages d'erreur)

# TLS (profil Mozilla "intermediate")
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:ACMESSL:10m;
ssl_session_tickets off;

# Limites anti-abus / slowloris
client_max_body_size 2m;
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 15s;
send_timeout 10s;
large_client_header_buffers 4 8k;

# Zones de limitation (utilisées dans le vhost)
limit_req_zone  $binary_remote_addr zone=acme_req:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=acme_conn:10m;
limit_req_status 429;
limit_conn_status 429;
EOF

    # --- En-têtes de sécurité (snippet à inclure dans chaque bloc server HTTPS)
    cat > /etc/nginx/snippets/acme-security-headers.conf <<'EOF'
# ACME - en-têtes de sécurité HTTP (vérification : https://securityheaders.com ou curl -I)
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
# CSP adaptée à un site statique : à ajuster si le site charge des ressources externes
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" always;
EOF

    # --- Certificat
    local crt=/etc/ssl/acme/acme-vitrine.crt key=/etc/ssl/acme/acme-vitrine.key autosigne=0
    install -d -m 750 /etc/ssl/acme
    if [[ ! -s "$crt" || ! -s "$key" ]]; then
        openssl req -x509 -newkey rsa:3072 -sha256 -days 397 -nodes \
            -keyout "$key" -out "$crt" -subj "/C=FR/O=ACME/CN=${SITE_NAME}" \
            -addext "subjectAltName=DNS:${SITE_NAME}" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
        autosigne=1
        warn "Certificat AUTO-SIGNÉ généré pour ${SITE_NAME} : remplacez $crt/$key par un certificat émis par votre AC interne (OPNsense ou AD CS) pour un HTTPS 'valide'"
    fi
    chmod 600 "$key"; chmod 644 "$crt"
    # HSTS seulement avec un vrai certificat (avec un auto-signé, le navigateur bloquerait définitivement l'accès)
    if [[ $autosigne -eq 0 ]] && ! openssl verify -CAfile "$crt" "$crt" >/dev/null 2>&1; then
        grep -q Strict-Transport-Security /etc/nginx/snippets/acme-security-headers.conf || \
            echo 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' >> /etc/nginx/snippets/acme-security-headers.conf
    else
        grep -q Strict-Transport-Security /etc/nginx/snippets/acme-security-headers.conf || \
            echo '# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;  # à activer avec un certificat signé par l AC' >> /etc/nginx/snippets/acme-security-headers.conf
    fi

    # --- Vhost durci (optionnel)
    if [[ $DEPLOY_VHOST -eq 1 ]]; then
        local v6_80="" v6_443="" v6_def80="" reject=""
        if [[ $HAS_IPV6 -eq 1 ]]; then
            v6_80="listen [::]:80;"; v6_443="listen [::]:443 ssl http2;"; v6_def80="listen [::]:80 default_server;"
        fi
        # ssl_reject_handshake existe à partir de nginx 1.19.4 (24.04 : oui, 22.04 : non)
        if [[ "$(printf '%s\n' "1.19.4" "$ver" | sort -V | head -1)" == "1.19.4" ]]; then
            reject="server {
    listen 443 ssl default_server;
    ssl_reject_handshake on;           # refuse le TLS pour tout nom inconnu (scan par IP)
}"
        fi
        cat > /etc/nginx/sites-available/acme-vitrine.conf <<EOF
# ACME - site vitrine durci (généré par hardening-acme-ubuntu.sh)

# Requêtes sans nom de site valide (scan par adresse IP, en-tête Host forgé) : connexion fermée
server {
    listen 80 default_server;
    ${v6_def80}
    server_name _;
    return 444;
}
${reject}

# HTTP -> HTTPS
server {
    listen 80;
    ${v6_80}
    server_name ${SITE_NAME};
    location /.well-known/acme-challenge/ { root ${WEB_ROOT}; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    ${v6_443}
    server_name ${SITE_NAME};

    ssl_certificate     ${crt};
    ssl_certificate_key ${key};

    root  ${WEB_ROOT};
    index index.html index.htm;

    include snippets/acme-security-headers.conf;

    limit_req  zone=acme_req burst=20 nodelay;
    limit_conn acme_conn 20;

    # Seules les méthodes utiles à un site vitrine
    if (\$request_method !~ ^(GET|HEAD|POST)\$) { return 405; }

    # Fichiers cachés (.git, .env, .htaccess...) et fichiers de sauvegarde
    location ~ /\.(?!well-known) { deny all; return 404; }
    location ~* \.(bak|old|orig|save|swp|sql|log|ini|conf|env|dist|inc)\$ { deny all; return 404; }

    location / {
        try_files \$uri \$uri/ =404;
    }

    autoindex off;
    access_log /var/log/nginx/acme-vitrine.access.log;
    error_log  /var/log/nginx/acme-vitrine.error.log warn;
}
EOF
        ln -sf /etc/nginx/sites-available/acme-vitrine.conf /etc/nginx/sites-enabled/acme-vitrine.conf
        rm -f /etc/nginx/sites-enabled/default
        # Contenu en lecture seule pour le processus nginx (www-data)
        if [[ -d "$WEB_ROOT" ]]; then
            chown -R root:www-data "$WEB_ROOT"
            find "$WEB_ROOT" -type d -exec chmod 750 {} +
            find "$WEB_ROOT" -type f -exec chmod 640 {} +
            ok "$WEB_ROOT : propriétaire root, lecture seule pour www-data"
        fi
        ok "Vhost acme-vitrine déployé (site 'default' désactivé)"
    else
        info "Vhost existant conservé : ajoutez 'include snippets/acme-security-headers.conf;' dans son bloc server HTTPS (ou relancez avec --deploy-vhost)"
    fi

    # --- Sandbox systemd du service nginx
    mkdir -p /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/60-acme-hardening.conf <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
EOF
    if [[ "$WEB_ROOT" == /home/* ]]; then
        sed -i '/^ProtectHome=/d' /etc/systemd/system/nginx.service.d/60-acme-hardening.conf
    fi
    systemctl daemon-reload

    if nginx -t 2>"$REPORT_DIR/nginx-test.txt" && systemctl restart nginx; then
        ok "nginx redémarré avec la nouvelle configuration"
    else
        warn "nginx -t ou redémarrage en échec : restauration de la configuration précédente ($REPORT_DIR/nginx-test.txt)"
        rm -rf /etc/nginx && cp -a "$bak" /etc/nginx
        rm -f /etc/systemd/system/nginx.service.d/60-acme-hardening.conf
        systemctl daemon-reload; systemctl restart nginx
        return 1
    fi
    systemd-analyze security nginx.service --no-pager 2>/dev/null | tail -1 | sed 's/^/  /' || true
    if [[ $DEPLOY_VHOST -eq 1 ]]; then
        curl -skI --resolve "${SITE_NAME}:443:127.0.0.1" "https://${SITE_NAME}/" > "$REPORT_DIR/entetes-https.txt" || true
        ok "En-têtes HTTPS obtenus (preuve) : $REPORT_DIR/entetes-https.txt"
    fi
}

# =============================================================================
#  ÉTAPE 13 - Rôle wazuh : serveur
# =============================================================================
step_13_wazuh_serveur() {
    local svc
    for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$svc"; then ok "$svc actif"; else warn "$svc inactif ou absent"; fi
    done

    # L'indexer (9200) ne doit pas être joignable depuis le réseau sur une installation mono-nœud
    local osyml=/etc/wazuh-indexer/opensearch.yml
    if [[ -f "$osyml" ]]; then
        local nh; nh="$(awk -F: '/^network.host/{gsub(/[ "]/,"",$2); print $2}' "$osyml")"
        if [[ "$nh" == "0.0.0.0" ]]; then
            warn "wazuh-indexer écoute sur 0.0.0.0 : bloqué par UFW, mais préférez l'IP locale/127.0.0.1 (attention aux SAN du certificat)"
        else ok "wazuh-indexer : network.host = ${nh:-par défaut}"; fi
    fi

    # Réception du syslog du pare-feu OPNsense
    local oc=/var/ossec/etc/ossec.conf
    if [[ -n "$FW_SYSLOG" && -f "$oc" ]] && ! grep -q "<allowed-ips>${FW_SYSLOG}</allowed-ips>" "$oc"; then
        cp "$oc" "$REPORT_DIR/ossec.conf.avant"
        cat >> "$oc" <<EOF

<!-- ACME : réception du syslog d'ACME-FW01 (OPNsense) -->
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>${FW_SYSLOG}</allowed-ips>
  </remote>
</ossec_config>
EOF
        if systemctl restart wazuh-manager; then ok "Syslog OPNsense accepté depuis $FW_SYSLOG (514/udp)"
        else cp "$REPORT_DIR/ossec.conf.avant" "$oc"; systemctl restart wazuh-manager; warn "Ajout syslog annulé (redémarrage manager en échec)"; fi
    fi

    # Le dépôt Wazuh ne doit pas mettre à jour les composants séparément (versions à garder alignées)
    for svc in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
        pkg_installed "$svc" && apt-mark hold "$svc" >/dev/null
    done
    ok "Paquets Wazuh gelés (apt-mark hold) : mises à jour à faire de façon coordonnée"

    [[ -d /var/ossec/etc ]] && chmod -R o-rwx /var/ossec/etc
    info "À faire manuellement : changer les mots de passe par défaut -> /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a"
}

# =============================================================================
#  ÉTAPE 14 - Agent Wazuh
# =============================================================================
step_14_wazuh_agent() {
    [[ -n "$WAZUH_MANAGER" ]] || { info "Pas de --wazuh-manager : étape ignorée"; return 0; }
    if timeout 3 bash -c "</dev/tcp/${WAZUH_MANAGER}/1514" 2>/dev/null; then
        ok "Manager $WAZUH_MANAGER joignable sur 1514/tcp"
    else
        warn "Manager $WAZUH_MANAGER injoignable sur 1514/tcp : vérifier les règles OPNsense (DMZ -> Wazuh : 1514-1515/tcp)"
    fi

    if ! pkg_installed wazuh-agent; then
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        apt-get update -q >/dev/null
        WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$(hostname)" WAZUH_AGENT_GROUP="$WAZUH_GROUP" \
            apt-get install "${APT_OPTS[@]}" "wazuh-agent${WAZUH_VERSION:+=$WAZUH_VERSION}" >/dev/null
        ok "wazuh-agent installé et enregistré auprès de $WAZUH_MANAGER (groupe $WAZUH_GROUP)"
    else
        info "wazuh-agent déjà installé"
    fi
    apt-mark hold wazuh-agent >/dev/null
    ok "wazuh-agent gelé (sa version ne doit jamais dépasser celle du manager)"

    # Journaux supplémentaires collectés
    local oc=/var/ossec/etc/ossec.conf extra=""
    grep -q '/var/log/audit/audit.log' "$oc" || extra+="  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>\n"
    grep -q '/var/log/sudo.log' "$oc"       || extra+="  <localfile><log_format>syslog</log_format><location>/var/log/sudo.log</location></localfile>\n"
    if [[ "$ROLE" == "web" ]]; then
        grep -q '/var/log/nginx/acme-vitrine.access.log' "$oc" || extra+="  <localfile><log_format>syslog</log_format><location>/var/log/nginx/acme-vitrine.access.log</location></localfile>\n"
        grep -q '/var/log/nginx/acme-vitrine.error.log' "$oc"  || extra+="  <localfile><log_format>syslog</log_format><location>/var/log/nginx/acme-vitrine.error.log</location></localfile>\n"
    fi
    if [[ -n "$extra" ]]; then
        printf '\n<!-- ACME : journaux complémentaires -->\n<ossec_config>\n%b</ossec_config>\n' "$extra" >> "$oc"
        ok "Collecte ajoutée : audit.log, sudo.log$([[ $ROLE == web ]] && echo ', journaux nginx du site')"
    fi
    systemctl daemon-reload
    systemctl enable wazuh-agent >/dev/null 2>&1
    systemctl restart wazuh-agent
    sleep 3
    if systemctl is-active --quiet wazuh-agent; then ok "wazuh-agent actif"; else warn "wazuh-agent ne démarre pas : journalctl -u wazuh-agent"; fi
    info "Le module SCA de Wazuh affichera le score CIS Ubuntu de cette machine (preuve complémentaire à Lynis)"
}

# =============================================================================
#  ÉTAPE 15 - AIDE (optionnel)
# =============================================================================
step_15_aide() {
    apt_install aide aide-common
    info "Initialisation de la base AIDE (plusieurs minutes)..."
    aideinit -y -f >/dev/null 2>&1
    systemctl enable --now dailyaidecheck.timer >/dev/null 2>&1 || true
    ok "AIDE initialisé, vérification quotidienne (redondant si l'agent Wazuh et son FIM sont actifs)"
}

# =============================================================================
#  ÉTAPE 16 - Vérifications et audit final
# =============================================================================
step_16_verifications() {
    echo "  --- SSH"
    sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|allowgroups|maxauthtries|x11forwarding|loglevel) ' | sed 's/^/      /'
    echo "  --- Pare-feu";   ufw status | sed 's/^/      /'
    echo "  --- Noyau"
    for k in kernel.kptr_restrict net.ipv4.conf.all.accept_redirects net.ipv4.tcp_syncookies fs.suid_dumpable; do
        printf '      %-40s %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null)"
    done
    echo "  --- Services de sécurité"
    for s in auditd fail2ban apparmor unattended-upgrades wazuh-agent nginx; do
        systemctl cat "$s.service" >/dev/null 2>&1 && \
            printf '      %-22s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"
    done

    pkg_installed lynis || apt_install lynis
    info "Audit Lynis final..."
    lynis audit system --quiet --no-colors \
        --logfile "$REPORT_DIR/lynis-apres.log" --report-file "$REPORT_DIR/lynis-apres.dat" >/dev/null || true
    local avant apres
    apres="$(lynis_index "$REPORT_DIR/lynis-apres.dat")"
    avant="$(lynis_index "$REPORT_DIR/lynis-avant.dat")"
    [[ -z "$avant" ]] && avant="$(lynis_index "$(ls -1d /root/acme-hardening/*/lynis-avant.dat 2>/dev/null | head -1)")"
    ok "Indice Lynis : AVANT ${avant:-?}/100  ->  APRÈS ${apres:-?}/100"
    grep -E '^suggestion\[\]=' "$REPORT_DIR/lynis-apres.dat" 2>/dev/null | cut -d'|' -f1,2 | sed 's/suggestion\[\]=//' \
        > "$REPORT_DIR/lynis-suggestions-restantes.txt" || true
    info "Suggestions restantes à justifier dans le rapport : $REPORT_DIR/lynis-suggestions-restantes.txt"
}

# =============================================================================
#  Exécution
# =============================================================================
echo "${C_CYAN}hardening-acme-ubuntu.sh v$VERSION - $(hostname) - Ubuntu ${VERSION_ID}${C_RST}"
echo "  Rôle            : $ROLE"
echo "  Étapes          : ${STEPS[*]}"
echo "  Admin nominatif : $ADMIN_USER  (clé fournie : $([[ -n $ADMIN_PUBKEY ]] && echo oui || echo non))"
echo "  Réseau d'admin  : $ADMIN_NET   (port SSH $SSH_PORT)"
[[ -n "$WAZUH_MANAGER" ]] && echo "  Manager Wazuh   : $WAZUH_MANAGER"
echo "  Rapports        : $REPORT_DIR"
if [[ $ASSUME_YES -eq 0 && -t 0 ]]; then
    read -r -p "Snapshot Proxmox fait et console noVNC ouverte ? Continuer [o/N] " rep
    [[ "$rep" =~ ^[oOyY]$ ]] || { echo "Abandon."; exit 0; }
fi

run_step 0  step_00_audit_initial  "Audit initial Lynis"
run_step 1  step_01_sauvegarde     "Sauvegarde de /etc et prérequis"
run_step 2  step_02_mises_a_jour   "Mises à jour"
run_step 3  step_03_comptes        "Comptes et authentification"
run_step 4  step_04_ssh            "SSH"
run_step 5  step_05_parefeu        "Pare-feu UFW"
run_step 6  step_06_noyau          "Noyau (sysctl, modules, core dumps)"
run_step 7  step_07_fichiers       "Systèmes de fichiers et permissions"
run_step 8  step_08_services       "Services, paquets et bannières"
run_step 9  step_09_journaux       "Journalisation et audit"
run_step 10 step_10_fail2ban       "Fail2ban"
run_step 11 step_11_apparmor       "AppArmor"
run_step 12 step_12_nginx          "Rôle web : nginx"
run_step 13 step_13_wazuh_serveur  "Rôle wazuh : serveur"
run_step 14 step_14_wazuh_agent    "Agent Wazuh"
run_step 15 step_15_aide           "AIDE (optionnel)"
run_step 16 step_16_verifications  "Vérifications et audit final"

echo
echo "${C_CYAN}===== Bilan =====${C_RST}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "${C_RED}Étape(s) en échec :${C_RST}"; printf '   - %s\n' "${FAILED[@]}"
    printf '%s\n' "${FAILED[@]}" > "$REPORT_DIR/echecs.txt"
else
    echo "${C_GREEN}Toutes les étapes demandées se sont terminées sans erreur.${C_RST}"
fi
if [[ -s "$WARN_FILE" ]]; then
    echo "${C_YEL}Points d'attention :${C_RST}"; sed 's/^/   - /' "$WARN_FILE"
fi
echo
echo "Actions restantes :"
echo "   - REDÉMARRER (tmpfs /tmp, audit=1, règles d'audit immuables, noyau éventuel)"
echo "   - Tester une nouvelle connexion SSH avec $ADMIN_USER AVANT de fermer la session en cours"
[[ "$ROLE" == "web" ]] && echo "   - Remplacer le certificat auto-signé par un certificat de l'AC interne, puis tester sur https://www.ssllabs.com (si exposé) ou testssl.sh"
echo "   - Joindre $REPORT_DIR (Lynis avant/après, règles UFW, rapports SUID...) au dossier de preuves"
echo "Journal complet : $LOG"
