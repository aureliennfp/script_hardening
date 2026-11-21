#!/usr/bin/env bash
# =============================================================================
#  hardening-lxc.sh  -  Durcissement de conteneurs LXC Debian / Ubuntu (Proxmox)
#                       et des services qui y tournent
#
#  Services détectés automatiquement (via systemd, aucun chemin supposé) :
#     Apache (+ PHP), FreshRSS, Vaultwarden, Uptime Kuma, MySpeed, Docker
#  Le script lit dans systemd le dossier de travail, le fichier d'environnement
#  et les ports réellement en écoute de chaque service, puis n'applique que ce
#  qui concerne ce qu'il a trouvé. Un même script pour tous les conteneurs.
#
#  Deux modes :
#     DANS un conteneur  : sudo ./hardening-lxc.sh [options]
#     SUR l'hôte Proxmox : ./hardening-lxc.sh --host-audit   (lecture seule)
#
#  Étapes (conteneur) :
#     0  Détection + audit initial (Lynis, ports, services)
#     1  Sauvegarde de /etc et des configurations des services
#     2  Mises à jour + mises à jour de sécurité automatiques
#     3  Comptes et sessions
#     4  SSH (durci, ou désactivé s'il ne sert pas : pct enter suffit)
#     5  Réseau (sysctl propres au conteneur)
#     6  Pare-feu nftables (refus par défaut, ports des services détectés)
#     7  Services système, messagerie locale, journaux
#     8  Apache + PHP
#     9  FreshRSS
#     10 Vaultwarden
#     11 Sandbox systemd + compte dédié (Vaultwarden, Uptime Kuma, MySpeed)
#        -> chaque service est testé après modification, retour arrière auto si KO
#     12 Docker (rapport ; --docker-harden pour appliquer)
#     13 Vérifications, audit final, recommandations côté hôte
#
#  Ce qui ne se règle PAS depuis un conteneur (noyau, AppArmor, privilèges,
#  nesting...) est listé à la fin et vérifié par --host-audit sur l'hôte.
#
#  AVANT : snapshot depuis l'hôte   ->  pct snapshot <CTID> avant-hardening
#          (stockage ZFS / LVM-thin ; sur un stockage "dir", faire un vzdump)
#  En cas de souci, l'accès reste toujours possible depuis l'hôte : pct enter <CTID>
#
#  Exemples :
#    ./hardening-lxc.sh                                   # tout, réseau autorisé = sous-réseau du conteneur
#    ./hardening-lxc.sh --cloudflare                      # services publiés via Cloudflare Tunnel
#    ./hardening-lxc.sh --allow-from 192.168.10.0/24 --admin-net 192.168.20.0/24
#    ./hardening-lxc.sh --steps 6                         # uniquement le pare-feu
#    ./hardening-lxc.sh --host-audit                      # sur l'hôte Proxmox
# =============================================================================

set -uo pipefail
VERSION="1.0"

# -----------------------------------------------------------------------------
#  Paramètres
# -----------------------------------------------------------------------------
STEPS_ARG="0-13"
ALLOW_FROM=""          # réseaux autorisés à joindre les services (défaut : sous-réseau du conteneur)
ADMIN_NET=""           # réseaux autorisés en SSH (défaut : ALLOW_FROM)
SSH_MODE="auto"        # auto | harden | off
SSH_PUBKEY=""
EXTRA_PORTS=""         # ex. "8080,9000/udp"
CLOUDFLARE=0           # services publiés via Cloudflare Tunnel
TUNNEL_IPS=""          # IP du conteneur cloudflared s'il est séparé
VW_KEEP_SIGNUPS=0
NO_SANDBOX=0
DOCKER_HARDEN=0
NO_AUDIT=0
HOST_AUDIT=0
ASSUME_YES=0

usage() {
    sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'
Options :
  --steps LISTE            ex. "0-13" (défaut), "6", "8-11"
  --allow-from CIDR[,..]   réseaux autorisés vers les services (défaut : sous-réseau du conteneur)
  --admin-net CIDR[,..]    réseaux autorisés en SSH (défaut : = --allow-from)
  --ssh auto|harden|off    auto = durci si une clé existe ou si vous êtes connecté en SSH, sinon désactivé
  --ssh-pubkey CLÉ|FICHIER installe une clé publique pour root (puis SSH par clé uniquement)
  --extra-ports LISTE      ports supplémentaires à ouvrir, ex. "8080,51820/udp"
  --cloudflare             services publiés via Cloudflare Tunnel (vraie IP client dans les journaux)
  --tunnel-ip IP[,..]      IP du conteneur cloudflared s'il n'est pas dans ce conteneur
  --vw-keep-signups        ne pas fermer les inscriptions Vaultwarden
  --no-sandbox             ne pas toucher aux unités systemd des services (étape 11)
  --docker-harden          applique daemon.json durci (redémarre Docker et les conteneurs)
  --no-audit               pas d'audit Lynis
  --host-audit             audit en lecture seule des conteneurs, à lancer sur l'hôte Proxmox
  -y, --yes                pas de confirmation
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --steps)           STEPS_ARG="$2"; shift 2 ;;
        --allow-from)      ALLOW_FROM="$2"; shift 2 ;;
        --admin-net)       ADMIN_NET="$2"; shift 2 ;;
        --ssh)             SSH_MODE="$2"; shift 2 ;;
        --ssh-pubkey)      SSH_PUBKEY="$2"; shift 2 ;;
        --extra-ports)     EXTRA_PORTS="$2"; shift 2 ;;
        --cloudflare)      CLOUDFLARE=1; shift ;;
        --tunnel-ip)       TUNNEL_IPS="$2"; shift 2 ;;
        --vw-keep-signups) VW_KEEP_SIGNUPS=1; shift ;;
        --no-sandbox)      NO_SANDBOX=1; shift ;;
        --docker-harden)   DOCKER_HARDEN=1; shift ;;
        --no-audit)        NO_AUDIT=1; shift ;;
        --host-audit)      HOST_AUDIT=1; shift ;;
        -y|--yes)          ASSUME_YES=1; shift ;;
        -h|--help)         usage ;;
        *) echo "Option inconnue : $1 (voir --help)"; exit 1 ;;
    esac
done
[[ "$SSH_MODE" =~ ^(auto|harden|off)$ ]] || { echo "--ssh : auto, harden ou off"; exit 1; }

if [[ -t 1 ]]; then C_CYAN=$'\e[36m'; C_GREEN=$'\e[32m'; C_YEL=$'\e[33m'; C_RED=$'\e[31m'; C_BOLD=$'\e[1m'; C_RST=$'\e[0m'
else C_CYAN=""; C_GREEN=""; C_YEL=""; C_RED=""; C_BOLD=""; C_RST=""; fi

# =============================================================================
#  MODE HÔTE : audit en lecture seule des conteneurs Proxmox
# =============================================================================
if [[ $HOST_AUDIT -eq 1 ]]; then
    command -v pct >/dev/null || { echo "--host-audit se lance sur l'hôte Proxmox (commande pct introuvable)."; exit 1; }
    echo "${C_CYAN}Audit des conteneurs LXC - $(hostname) - $(pveversion 2>/dev/null | cut -d/ -f2)${C_RST}"
    echo
    cluster_fw="non"
    grep -Eq '^\s*enable:\s*1' /etc/pve/firewall/cluster.fw 2>/dev/null && cluster_fw="oui"
    printf '%s\n' "Pare-feu Proxmox activé au niveau datacenter : $cluster_fw"
    [[ "$cluster_fw" == "non" ]] && echo "  ${C_YEL}-> Datacenter > Pare-feu > Options > Pare-feu : Oui (sinon les règles par conteneur ne s'appliquent pas)${C_RST}"
    echo
    printf "${C_BOLD}%-6s %-18s %-22s %-6s %-14s %-9s %-5s %s${C_RST}\n" "CTID" "Nom" "Tags" "Priv." "Features" "Pare-feu" "Prot." "Alertes"
    for id in $(pct list | awk 'NR>1{print $1}'); do
        conf="$(pct config "$id" 2>/dev/null)"
        name="$(awk -F': ' '/^hostname:/{print $2}' <<<"$conf")"
        tags="$(awk -F': ' '/^tags:/{print $2}' <<<"$conf")"
        feat="$(awk -F': ' '/^features:/{print $2}' <<<"$conf")"
        alerts=()
        if grep -q '^unprivileged: 1' <<<"$conf"; then priv="non"
        else priv="${C_RED}OUI${C_RST}"; alerts+=("conteneur PRIVILÉGIÉ (root du CT ~ root de l'hôte)"); fi
        nics_fw="oui"
        while read -r l; do [[ -n "$l" && "$l" != *firewall=1* ]] && nics_fw="non"; done < <(grep -E '^net[0-9]+:' <<<"$conf")
        [[ -f /etc/pve/firewall/$id.fw ]] && grep -Eq '^\s*enable:\s*1' "/etc/pve/firewall/$id.fw" || nics_fw="${nics_fw}/off"
        prot="non"; grep -q '^protection: 1' <<<"$conf" && prot="oui"
        [[ "$feat" == *keyctl=1* ]] && alerts+=("keyctl=1 (utile seulement pour Docker)")
        [[ "$feat" == *fuse=1* ]]   && alerts+=("fuse=1")
        [[ "$feat" == *mount=* ]]   && alerts+=("montages NFS/CIFS autorisés dans le CT")
        grep -q 'lxc.apparmor.profile: *unconfined' <<<"$conf" && alerts+=("${C_RED}AppArmor DÉSACTIVÉ (unconfined)${C_RST}")
        grep -Eq '^lxc.cap.drop: *$' <<<"$conf"                 && alerts+=("${C_RED}capabilities non restreintes (lxc.cap.drop vide)${C_RST}")
        grep -q '^lxc.cgroup2.devices.allow' <<<"$conf"         && alerts+=("périphériques de l'hôte exposés")
        grep -Eq '^mp[0-9]+:' <<<"$conf"                        && alerts+=("points de montage hôte : $(grep -cE '^mp[0-9]+:' <<<"$conf")")
        printf "%-6s %-18s %-22s %-6s %-14s %-9s %-5s %s\n" "$id" "${name:0:18}" "${tags:0:22}" "$priv" "${feat:-aucune}" "$nics_fw" "$prot" "$(printf '%s ; ' "${alerts[@]}" | sed 's/ ; $//')"
    done
    echo
    echo "${C_BOLD}Lecture :${C_RST}"
    echo "  Priv.     : un CT privilégié se convertit par sauvegarde puis restauration : pct restore <ID> <backup> --unprivileged 1"
    echo "  Features  : nesting=1 est requis par systemd récent (Debian 12+) et Docker ; keyctl=1 seulement pour Docker"
    echo "  Pare-feu  : 'oui' = firewall=1 sur les cartes réseau ET règles actives dans /etc/pve/firewall/<ID>.fw"
    echo "              (contrairement à nftables dans le CT, root du conteneur ne peut pas le désactiver)"
    echo "  Prot.     : protection contre la suppression accidentelle -> pct set <ID> --protection 1"
    echo
    echo "${C_BOLD}Paramètres noyau de l'hôte (partagés par tous les conteneurs) :${C_RST}"
    for kv in kernel.dmesg_restrict=1 kernel.kptr_restrict=1 kernel.unprivileged_bpf_disabled=1 \
              net.core.bpf_jit_harden=2 kernel.yama.ptrace_scope=1 fs.protected_symlinks=1 \
              fs.protected_hardlinks=1 fs.suid_dumpable=0 kernel.kexec_load_disabled=1; do
        k="${kv%%=*}"; want="${kv#*=}"; cur="$(sysctl -n "$k" 2>/dev/null || echo '?')"
        if [[ "$cur" == "$want" || ( "$k" == kernel.kptr_restrict && "$cur" == 2 ) || ( "$k" == kernel.unprivileged_bpf_disabled && "$cur" == 2 ) ]]; then
            printf "  ${C_GREEN}[OK]${C_RST} %-36s %s\n" "$k" "$cur"
        else
            printf "  ${C_YEL}[!]${C_RST}  %-36s %s (recommandé : %s)\n" "$k" "$cur" "$want"
        fi
    done
    echo "  -> à mettre dans /etc/sysctl.d/90-hardening.conf de l'hôte, puis : sysctl --system"
    echo "     kernel.dmesg_restrict=1 est le plus important : sans lui, les conteneurs lisent les journaux noyau de l'hôte."
    exit 0
fi

# =============================================================================
#  MODE CONTENEUR
# =============================================================================
[[ $EUID -eq 0 ]] || { echo "À lancer en root (dans le conteneur : pct enter <CTID>, ou sudo)."; exit 1; }
. /etc/os-release
[[ "${ID:-}" =~ ^(debian|ubuntu)$ ]] || { echo "Debian ou Ubuntu requis (détecté : ${ID:-?})"; exit 1; }

STEPS=()
IFS=',' read -ra _parts <<< "$STEPS_ARG"
for p in "${_parts[@]}"; do
    if [[ "$p" =~ ^([0-9]+)-([0-9]+)$ ]]; then for ((i=BASH_REMATCH[1]; i<=BASH_REMATCH[2]; i++)); do STEPS+=("$i"); done
    elif [[ "$p" =~ ^[0-9]+$ ]]; then STEPS+=("$p")
    else echo "Étapes invalides : $STEPS_ARG"; exit 1; fi
done

STAMP="$(date +%Y%m%d-%H%M%S)"
BASE_DIR="/root/hardening-lxc"
REPORT_DIR="$BASE_DIR/$STAMP"
mkdir -p "$REPORT_DIR"; chmod 700 "$BASE_DIR"
LOG="$REPORT_DIR/hardening.log"
WARN_FILE="$REPORT_DIR/avertissements.txt"; : > "$WARN_FILE"
HOST_FILE="$REPORT_DIR/a-faire-sur-l-hote.txt"; : > "$HOST_FILE"
exec > >(tee -a "$LOG") 2>&1

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
CONF_DIR="/etc/lxc-hardening"; mkdir -p "$CONF_DIR"

section() { echo; echo "${C_CYAN}===== Étape $1 : $2 =====${C_RST}"; }
ok()      { echo "  ${C_GREEN}[OK]${C_RST} $*"; }
info()    { echo "  ${C_YEL}[i]${C_RST}  $*"; }
warn()    { echo "  ${C_RED}[!]${C_RST}  $*"; echo "$*" >> "$WARN_FILE"; }
host_todo() { echo "$*" >> "$HOST_FILE"; }

apt_install()   { apt-get install "${APT_OPTS[@]}" --no-install-recommends "$@" >/dev/null; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
unit_exists()   { [[ -n "$1" ]] && systemctl cat "$1" >/dev/null 2>&1; }

set_kv() {   # set_kv fichier clé valeur [séparateur] - remplace la ligne active ou ajoute
    local f="$1" k="$2" v="$3" sep="${4:- }" re
    re="${sep// /}"; [[ -z "$re" ]] && re="[[:space:]]"
    touch "$f"
    if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${k}[[:space:]]*${re}" "$f"; then
        sed -ri "s|^[[:space:]]*(export[[:space:]]+)?${k}[[:space:]]*${re}.*|${k}${sep}${v}|" "$f"
    else
        echo "${k}${sep}${v}" >> "$f"
    fi
}
get_env() {   # get_env fichier clé -> valeur sans guillemets
    grep -E "^[[:space:]]*(export[[:space:]]+)?$2[[:space:]]*=" "$1" 2>/dev/null | tail -1 | cut -d= -f2- \
        | sed -E "s/^[[:space:]]*['\"]?//; s/['\"]?[[:space:]]*$//" || true
}
ip_in_nets() {   # ip_in_nets IP "cidr1,cidr2"
    python3 - "$1" "$2" <<'PY' 2>/dev/null
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    nets = [n.strip() for n in sys.argv[2].split(',') if n.strip()]
    sys.exit(0 if any(ip.version == ipaddress.ip_network(n, strict=False).version and ip in ipaddress.ip_network(n, strict=False) for n in nets) else 1)
except Exception:
    sys.exit(1)
PY
}

# PIDs d'une unité (cgroup v2, sinon processus principal et ses enfants)
unit_pids() {
    local cg; cg="$(systemctl show -p ControlGroup --value "$1" 2>/dev/null)"
    if [[ -n "$cg" && -r "/sys/fs/cgroup$cg/cgroup.procs" ]]; then cat "/sys/fs/cgroup$cg/cgroup.procs"
    else
        local m; m="$(systemctl show -p MainPID --value "$1" 2>/dev/null)"
        [[ -n "$m" && "$m" != 0 ]] && { echo "$m"; pgrep -P "$m" || true; }
    fi
    return 0
}
# Sockets TCP en écoute d'une unité -> "adresse port" par ligne
unit_listen() {
    local pids; pids="$(unit_pids "$1" | sort -u)"
    [[ -z "$pids" ]] && return 0
    ss -Htlnp 2>/dev/null | awk '{print $4, $NF}' | while read -r addr users; do
        for p in $(grep -oE 'pid=[0-9]+' <<<"$users" | cut -d= -f2); do
            if grep -qx "$p" <<<"$pids"; then echo "${addr%:*} ${addr##*:}"; break; fi
        done
    done | sort -u
}
is_loopback() { [[ "$1" == 127.* || "$1" == "[::1]" || "$1" == "::1" ]]; }
public_ports() { unit_listen "$1" | while read -r a p; do is_loopback "$a" || echo "$p"; done | sort -un | tr '\n' ' '; }

current_ssh_peers() {
    ss -Htn state established 2>/dev/null | awk '{print $3, $4}' | while read -r l r; do
        [[ "${l##*:}" == "$SSH_PORT_CUR" ]] && echo "${r%:*}" | sed -E 's/^\[//; s/\]$//; s/^::ffff://'
    done | sort -u
}
lynis_index() { grep -E '^hardening_index=' "$1" 2>/dev/null | cut -d= -f2 || true; }

FAILED=()
run_step() {
    local n="$1" fn="$2" title="$3" rc
    [[ " ${STEPS[*]} " == *" $n "* ]] || return 0
    section "$n" "$title"
    ( set -Eeuo pipefail
      trap 'echo "  ${C_RED}[ERREUR]${C_RST} ligne $LINENO : $BASH_COMMAND" >&2' ERR
      "$fn" )
    rc=$?
    [[ $rc -ne 0 ]] && FAILED+=("Étape $n - $title (code $rc)")
    return 0
}

# =============================================================================
#  Détection (avant toute modification)
# =============================================================================
VIRT="$(systemd-detect-virt -c 2>/dev/null || echo none)"
PRIVILEGED=0
read -r _u0 _u1 _ < /proc/self/uid_map 2>/dev/null && [[ "$_u0" == 0 && "$_u1" == 0 ]] && PRIVILEGED=1
[[ "$VIRT" != "lxc" ]] && PRIVILEGED=0

find_unit() {   # premier service dont le nom correspond au motif
    systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' \
        | grep -iE "$1" | grep -v '@' | head -1 || true
}
UNIT_APACHE="";  unit_exists apache2.service && UNIT_APACHE="apache2.service"
UNIT_VW="$(find_unit '^vaultwarden')"
UNIT_KUMA="$(find_unit '^(uptime-?kuma|kuma)')"
UNIT_MYSPEED="$(find_unit '^myspeed')"
UNIT_CLOUDFLARED="$(find_unit '^cloudflared')"
HAS_DOCKER=0; command -v docker >/dev/null 2>&1 && HAS_DOCKER=1

FRESHRSS_DIR=""
for d in /opt/freshrss /opt/FreshRSS /var/www/FreshRSS /var/www/freshrss /var/www/html/FreshRSS /usr/share/FreshRSS; do
    if [[ -f "$d/constants.php" ]] && grep -q 'FRESHRSS_VERSION' "$d/constants.php" 2>/dev/null; then FRESHRSS_DIR="$d"; break; fi
done
if [[ -z "$FRESHRSS_DIR" ]]; then
    f="$(find /opt /var/www /usr/share -maxdepth 4 -name constants.php -exec grep -l 'FRESHRSS_VERSION' {} + 2>/dev/null | head -1 || true)"
    [[ -n "$f" ]] && FRESHRSS_DIR="$(dirname "$f")"
fi

# Réseau du conteneur
DEF_IF="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
LAN_CIDR="$(ip -o -4 addr show dev "${DEF_IF:-eth0}" 2>/dev/null | awk '{print $4; exit}')"
if [[ -n "$LAN_CIDR" ]]; then
    LAN_CIDR="$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$LAN_CIDR" 2>/dev/null || echo "$LAN_CIDR")"
fi
[[ -z "$ALLOW_FROM" ]] && ALLOW_FROM="${LAN_CIDR:-192.168.0.0/16}"
[[ -z "$ADMIN_NET" ]] && ADMIN_NET="$ALLOW_FROM"
IPV6_SLAAC=0; ip -o -6 addr show scope global 2>/dev/null | grep -q dynamic && IPV6_SLAAC=1

SSH_UNIT=""; unit_exists ssh.service && SSH_UNIT="ssh"
SSH_PORT_CUR="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"; SSH_PORT_CUR="${SSH_PORT_CUR:-22}"
SSH_ACTIVE=0
{ systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; } 2>/dev/null && SSH_ACTIVE=1
IN_SSH_SESSION=0; [[ -n "${SSH_CONNECTION:-}" ]] && IN_SSH_SESSION=1

if [[ -n "$SSH_PUBKEY" && -f "$SSH_PUBKEY" ]]; then SSH_PUBKEY="$(cat "$SSH_PUBKEY")"; fi

# Ports actuels de chaque service (référence pour les tests après modification)
declare -A PORTS_BEFORE
for u in $UNIT_APACHE $UNIT_VW $UNIT_KUMA $UNIT_MYSPEED; do PORTS_BEFORE[$u]="$(public_ports "$u")"; done

# =============================================================================
#  ÉTAPE 0 - Détection et audit initial
# =============================================================================
step_00_detection() {
    ok "Système : $PRETTY_NAME - virtualisation : $VIRT"
    if [[ "$VIRT" != "lxc" ]]; then warn "Ce n'est pas un conteneur LXC : le script fonctionne, mais hardening-acme-ubuntu.sh est plus adapté à une VM"; fi
    if [[ $PRIVILEGED -eq 1 ]]; then
        warn "Conteneur PRIVILÉGIÉ : root ici est très proche de root sur l'hôte. À convertir en non privilégié (voir fin du rapport)"
        host_todo "Convertir ce conteneur en NON privilégié : vzdump <CTID> puis pct restore <CTID> <archive> --unprivileged 1 --force"
    else ok "Conteneur non privilégié"; fi
    echo "  Services détectés :"
    printf '      %-14s %s\n' "Apache" "${UNIT_APACHE:-non}" "FreshRSS" "${FRESHRSS_DIR:-non}" \
        "Vaultwarden" "${UNIT_VW:-non}" "Uptime Kuma" "${UNIT_KUMA:-non}" "MySpeed" "${UNIT_MYSPEED:-non}" \
        "cloudflared" "${UNIT_CLOUDFLARED:-non}" "Docker" "$([[ $HAS_DOCKER -eq 1 ]] && echo oui || echo non)"
    for u in "${!PORTS_BEFORE[@]}"; do [[ -n "${PORTS_BEFORE[$u]}" ]] && echo "      ports $u : ${PORTS_BEFORE[$u]}"; done
    echo "  Réseau : $DEF_IF $LAN_CIDR  ->  services ouverts à $ALLOW_FROM, SSH à $ADMIN_NET"

    if ls /etc/systemd/system/container-getty@*.service.d/*.conf >/dev/null 2>&1 && \
       grep -qs -- '--autologin' /etc/systemd/system/container-getty@*.service.d/*.conf; then
        info "Console Proxmox en connexion automatique root (scripts communautaires) : quiconque accède à l'interface Proxmox a un shell root ici"
    fi

    ss -tulpn > "$REPORT_DIR/ports-avant.txt"
    systemctl list-units --type=service --state=running --no-legend > "$REPORT_DIR/services-avant.txt"
    if [[ $NO_AUDIT -eq 0 ]]; then
        apt-get update -q >/dev/null
        pkg_installed lynis || apt_install lynis
        info "Audit Lynis (1 à 2 minutes)..."
        lynis audit system --quiet --no-colors --logfile "$REPORT_DIR/lynis-avant.log" \
            --report-file "$REPORT_DIR/lynis-avant.dat" >/dev/null 2>&1 || true
        ok "Indice Lynis AVANT : $(lynis_index "$REPORT_DIR/lynis-avant.dat")/100"
    fi
}

# =============================================================================
#  ÉTAPE 1 - Sauvegarde
# =============================================================================
step_01_sauvegarde() {
    local extra=()
    for u in $UNIT_VW $UNIT_KUMA $UNIT_MYSPEED; do
        local ef; ef="$(systemctl show -p EnvironmentFiles --value "$u" 2>/dev/null | awk '{print $1}')"
        [[ -n "$ef" && -f "$ef" ]] && extra+=("${ef#/}")
    done
    [[ -n "$FRESHRSS_DIR" && -f "$FRESHRSS_DIR/data/config.php" ]] && extra+=("${FRESHRSS_DIR#/}/data/config.php")
    tar -czpf "$REPORT_DIR/sauvegarde-config.tar.gz" -C / etc "${extra[@]}" 2>/dev/null || true
    chmod 600 "$REPORT_DIR/sauvegarde-config.tar.gz"
    ok "Configurations sauvegardées : $REPORT_DIR/sauvegarde-config.tar.gz (restauration : tar -xzpf <archive> -C /)"
    apt-get update -q >/dev/null
    apt_install ca-certificates curl python3 iproute2 nftables procps
    ok "Prérequis présents"
}

# =============================================================================
#  ÉTAPE 2 - Mises à jour
# =============================================================================
step_02_mises_a_jour() {
    apt-get update -q >/dev/null
    apt-get "${APT_OPTS[@]}" full-upgrade >/dev/null
    apt-get "${APT_OPTS[@]}" autoremove --purge >/dev/null
    ok "Paquets système à jour"
    apt_install unattended-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    cat > /etc/apt/apt.conf.d/52unattended-upgrades-lxc <<'EOF'
// Mises à jour de SÉCURITÉ automatiques uniquement, sans redémarrage
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF
    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    ok "Mises à jour de sécurité automatiques activées"
    [[ -n "$UNIT_VW$UNIT_KUMA$UNIT_MYSPEED$FRESHRSS_DIR" ]] && \
        info "Vaultwarden / Uptime Kuma / MySpeed / FreshRSS ne passent pas par apt : mettez-les à jour avec leur propre procédure (commande 'update' des scripts communautaires)"
    return 0
}

# =============================================================================
#  ÉTAPE 3 - Comptes et sessions
# =============================================================================
step_03_comptes() {
    local u
    while IFS=: read -r u pw _; do
        if [[ -z "$pw" ]]; then passwd -l "$u" >/dev/null; warn "Compte $u sans mot de passe : verrouillé"; fi
    done < /etc/shadow
    ok "Aucun compte sans mot de passe"
    local others; others="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)"
    [[ -n "$others" ]] && warn "Comptes avec UID 0 autres que root : $others"

    sed -ri 's/^#?\s*ENCRYPT_METHOD\s.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
    grep -q '^ENCRYPT_METHOD' /etc/login.defs || echo 'ENCRYPT_METHOD YESCRYPT' >> /etc/login.defs
    sed -ri 's/^#?\s*UMASK\s.*/UMASK 027/' /etc/login.defs
    cat > /etc/profile.d/99-lxc-hardening.sh <<'EOF'
# Shells inactifs fermés après 15 min ; fichiers créés non lisibles par "autres"
if [ "${TMOUT:-}" != "900" ]; then TMOUT=900; readonly TMOUT; export TMOUT; fi
umask 027
EOF
    ok "Mots de passe hachés en yescrypt, umask 027, shells inactifs fermés après 15 min"

    if command -v sudo >/dev/null; then
        cat > /etc/sudoers.d/50-lxc-hardening <<'EOF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=5
EOF
        chmod 440 /etc/sudoers.d/50-lxc-hardening
        visudo -cq || { rm -f /etc/sudoers.d/50-lxc-hardening; echo "sudoers invalide"; return 1; }
        ok "sudo journalisé dans /var/log/sudo.log"
    fi
    chmod 700 /root
    ok "/root en 700"
}

# =============================================================================
#  ÉTAPE 4 - SSH
# =============================================================================
step_04_ssh() {
    if [[ -z "$SSH_UNIT" ]]; then info "OpenSSH non installé : accès par pct enter / console Proxmox uniquement (très bien)"; return 0; fi

    if [[ -n "$SSH_PUBKEY" ]]; then
        install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
        grep -qF "$SSH_PUBKEY" /root/.ssh/authorized_keys || echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
        ok "Clé publique installée pour root"
    fi
    local has_key=0 h
    for h in /root $(awk -F: '$3>=1000 && $3<65534{print $6}' /etc/passwd); do
        [[ -s "$h/.ssh/authorized_keys" ]] && has_key=1
    done

    local mode="$SSH_MODE"
    if [[ "$mode" == "auto" ]]; then
        if [[ $has_key -eq 1 || $IN_SSH_SESSION -eq 1 ]]; then mode="harden"; else mode="off"; fi
    fi
    if [[ "$mode" == "off" && $IN_SSH_SESSION -eq 1 ]]; then
        warn "Vous êtes connecté en SSH : SSH n'est pas désactivé (relancez depuis pct enter avec --ssh off)"
        mode="harden"
    fi

    if [[ "$mode" == "off" ]]; then
        systemctl disable --now ssh.socket ssh.service >/dev/null 2>&1 || true
        systemctl mask ssh.service ssh.socket >/dev/null 2>&1 || true
        ok "SSH désactivé : aucune clé configurée et l'accès reste possible par 'pct enter <CTID>' depuis l'hôte"
        info "Pour le réactiver : systemctl unmask ssh.service && systemctl enable --now ssh"
        return 0
    fi

    local pwauth="no" prl="prohibit-password"
    if [[ $has_key -eq 0 ]]; then
        pwauth="yes"
        prl="$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2; exit}' || true)"; prl="${prl:-prohibit-password}"
        warn "Aucune clé SSH : mot de passe CONSERVÉ (PermitRootLogin $prl inchangé). Ajoutez une clé (--ssh-pubkey) puis relancez --steps 4"
    fi
    grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || \
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-lxc-hardening.conf <<EOF
# Durcissement OpenSSH (prioritaire : la première valeur lue l'emporte)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
PermitRootLogin ${prl}
PasswordAuthentication ${pwauth}
PermitEmptyPasswords no
KbdInteractiveAuthentication no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
LogLevel VERBOSE
EOF
    if ! sshd -t; then
        mv /etc/ssh/sshd_config.d/00-lxc-hardening.conf "$REPORT_DIR/sshd-rejete.conf"
        echo "Configuration SSH invalide, retirée"; return 1
    fi
    systemctl reload ssh 2>/dev/null || systemctl restart ssh
    ok "SSH durci (mot de passe : $pwauth, PermitRootLogin $prl, algorithmes modernes)"
}

# =============================================================================
#  ÉTAPE 5 - Réseau (sysctl propres au conteneur)
# =============================================================================
step_05_reseau() {
    local params=(
        net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0
        net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0
        net.ipv4.conf.all.send_redirects=0   net.ipv4.conf.default.send_redirects=0
        net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0
        net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
        net.ipv4.conf.all.log_martians=1 net.ipv4.icmp_echo_ignore_broadcasts=1
        net.ipv4.icmp_ignore_bogus_error_responses=1 net.ipv4.tcp_syncookies=1 net.ipv4.tcp_rfc1337=1
        net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
        net.ipv6.conf.all.accept_source_route=0
    )
    [[ $IPV6_SLAAC -eq 0 ]] && params+=(net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0)
    [[ $HAS_DOCKER -eq 0 ]] && params+=(net.ipv4.ip_forward=0)
    local f=/etc/sysctl.d/60-lxc-hardening.conf p ignores=()
    echo "# Paramètres réseau propres au conteneur (les paramètres noyau se règlent sur l'hôte)" > "$f"
    for p in "${params[@]}"; do
        if sysctl -qw "$p" >/dev/null 2>&1; then echo "$p" >> "$f"; else ignores+=("${p%%=*}"); fi
    done
    ok "$(grep -c '=' "$f") paramètres réseau appliqués (redirections ICMP, routage source, SYN cookies...)"
    [[ ${#ignores[@]} -gt 0 ]] && info "Non modifiables depuis le conteneur (à régler sur l'hôte) : ${ignores[*]}"
    [[ $IPV6_SLAAC -eq 1 ]] && info "IPv6 en autoconfiguration (SLAAC) : annonces de routeur conservées"
    host_todo "Sur l'hôte : ./hardening-lxc.sh --host-audit (paramètres noyau partagés : dmesg_restrict, kptr_restrict, bpf...)"
    return 0
}

# =============================================================================
#  ÉTAPE 6 - Pare-feu nftables
# =============================================================================
step_06_parefeu() {
    if systemctl is-active --quiet ufw 2>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
        info "UFW déjà actif dans ce conteneur : pare-feu nftables non ajouté (pas de double filtrage)"; return 0
    fi
    if ! nft list tables >/dev/null 2>&1; then
        warn "nftables inutilisable dans ce conteneur : utilisez le pare-feu Proxmox (règles prêtes dans $REPORT_DIR/pve-firewall-CTID.fw)"
    fi

    # Ports à ouvrir : ceux des services détectés + --extra-ports
    local tcp=() udp=() u p
    for u in $UNIT_APACHE $UNIT_VW $UNIT_KUMA $UNIT_MYSPEED; do
        for p in ${PORTS_BEFORE[$u]:-}; do tcp+=("$p"); done
    done
    for p in ${EXTRA_PORTS//,/ }; do
        if [[ "$p" == */udp ]]; then udp+=("${p%/udp}"); else tcp+=("${p%/tcp}"); fi
    done
    mapfile -t tcp < <(printf '%s\n' "${tcp[@]}" | grep -E '^[0-9]+$' | sort -un)
    mapfile -t udp < <(printf '%s\n' "${udp[@]}" | grep -E '^[0-9]+$' | sort -un)
    local ssh_on=0
    systemctl is-active --quiet ssh.service 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null && ssh_on=1
    SSH_PORT_CUR="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"; SSH_PORT_CUR="${SSH_PORT_CUR:-22}"

    # Listes d'adresses (v4 / v6)
    local a4=() a6=() m4=() m6=() n peer
    for n in ${ALLOW_FROM//,/ } ${TUNNEL_IPS//,/ }; do [[ "$n" == *:* ]] && a6+=("$n") || a4+=("$n"); done
    for n in ${ADMIN_NET//,/ }; do [[ "$n" == *:* ]] && m6+=("$n") || m4+=("$n"); done
    if [[ $ssh_on -eq 1 ]]; then
        for peer in $(current_ssh_peers); do
            if ! ip_in_nets "$peer" "$ADMIN_NET"; then
                [[ "$peer" == *:* ]] && m6+=("$peer") || m4+=("$peer")
                warn "Session SSH en cours depuis $peer (hors $ADMIN_NET) : autorisée pour ne pas vous couper"
            fi
        done
    fi
    join() { local IFS=','; echo "$*"; }

    local nftf="$CONF_DIR/firewall.nft"
    {
        echo "#!/usr/sbin/nft -f"
        echo "# Pare-feu du conteneur $(hostname) - généré par hardening-lxc.sh v$VERSION le $(date '+%F %T')"
        echo "# Ne touche qu'à sa propre table : compatible Docker et autres règles."
        echo "table inet lxc_hardening"
        echo "delete table inet lxc_hardening"
        echo "table inet lxc_hardening {"
        [[ ${#a4[@]} -gt 0 ]] && echo "    set allow4 { type ipv4_addr; flags interval; auto-merge; elements = { $(join "${a4[@]}") } }"
        [[ ${#m4[@]} -gt 0 ]] && echo "    set admin4 { type ipv4_addr; flags interval; auto-merge; elements = { $(join "${m4[@]}") } }"
        [[ ${#a6[@]} -gt 0 ]] && echo "    set allow6 { type ipv6_addr; flags interval; auto-merge; elements = { $(join "${a6[@]}") } }"
        [[ ${#m6[@]} -gt 0 ]] && echo "    set admin6 { type ipv6_addr; flags interval; auto-merge; elements = { $(join "${m6[@]}") } }"
        echo ""
        echo "    chain input {"
        echo "        type filter hook input priority filter; policy drop;"
        echo "        iif \"lo\" accept"
        echo "        ct state established,related accept"
        echo "        ct state invalid drop"
        echo "        meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big, destination-unreachable, time-exceeded } accept"
        [[ ${#a4[@]} -gt 0 ]] && echo "        ip saddr @allow4 icmp type { echo-request, destination-unreachable, time-exceeded } accept   # ping (Uptime Kuma)"
        [[ ${#a6[@]} -gt 0 ]] && echo "        ip6 saddr @allow6 icmpv6 type echo-request accept"
        echo "        udp dport 68 accept   # renouvellement DHCP"
        [[ $HAS_DOCKER -eq 1 ]] && echo "        iifname { \"docker0\", \"br-*\" } accept   # conteneurs Docker locaux"
        if [[ $ssh_on -eq 1 ]]; then
            [[ ${#m4[@]} -gt 0 ]] && echo "        ip saddr @admin4 tcp dport $SSH_PORT_CUR accept   # SSH"
            [[ ${#m6[@]} -gt 0 ]] && echo "        ip6 saddr @admin6 tcp dport $SSH_PORT_CUR accept"
        fi
        if [[ ${#tcp[@]} -gt 0 ]]; then
            [[ ${#a4[@]} -gt 0 ]] && echo "        ip saddr @allow4 tcp dport { $(join "${tcp[@]}") } accept   # services"
            [[ ${#a6[@]} -gt 0 ]] && echo "        ip6 saddr @allow6 tcp dport { $(join "${tcp[@]}") } accept"
        fi
        if [[ ${#udp[@]} -gt 0 ]]; then
            [[ ${#a4[@]} -gt 0 ]] && echo "        ip saddr @allow4 udp dport { $(join "${udp[@]}") } accept"
            [[ ${#a6[@]} -gt 0 ]] && echo "        ip6 saddr @allow6 udp dport { $(join "${udp[@]}") } accept"
        fi
        echo "        counter comment \"refuses\""
        echo "    }"
        if [[ $HAS_DOCKER -eq 0 ]]; then
            echo "    chain forward { type filter hook forward priority filter; policy drop; }"
        fi
        echo "}"
    } > "$nftf"
    chmod 600 "$nftf"

    # Règles équivalentes pour le pare-feu Proxmox (défense en profondeur, côté hôte)
    {
        echo "# À copier dans /etc/pve/firewall/<CTID>.fw sur l'hôte, puis : pct set <CTID> --net0 ...,firewall=1"
        echo "[OPTIONS]"; echo "enable: 1"; echo "policy_in: DROP"; echo "policy_out: ACCEPT"; echo
        echo "[RULES]"
        local s
        for s in ${ALLOW_FROM//,/ } ${TUNNEL_IPS//,/ }; do
            echo "IN ACCEPT -source $s -p icmp -log nolog"
            for p in "${tcp[@]}"; do echo "IN ACCEPT -source $s -p tcp -dport $p -log nolog"; done
            for p in "${udp[@]}"; do echo "IN ACCEPT -source $s -p udp -dport $p -log nolog"; done
        done
        [[ $ssh_on -eq 1 ]] && for s in ${ADMIN_NET//,/ }; do echo "IN ACCEPT -source $s -p tcp -dport $SSH_PORT_CUR -log nolog"; done
    } > "$REPORT_DIR/pve-firewall-CTID.fw"
    host_todo "Pare-feu Proxmox pour ce conteneur (root du CT ne peut pas le couper) : $REPORT_DIR/pve-firewall-CTID.fw"

    nft list tables >/dev/null 2>&1 || return 0
    if ! nft -c -f "$nftf" 2>"$REPORT_DIR/nft-erreur.txt"; then
        echo "Règles nftables refusées (voir $REPORT_DIR/nft-erreur.txt) : rien n'a été appliqué"; return 1
    fi
    cat > /etc/systemd/system/lxc-hardening-firewall.service <<EOF
[Unit]
Description=Pare-feu nftables du conteneur (hardening-lxc)
Wants=network-pre.target
Before=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $nftf
ExecStop=/usr/sbin/nft delete table inet lxc_hardening

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable lxc-hardening-firewall >/dev/null 2>&1
    systemctl restart lxc-hardening-firewall
    ok "Pare-feu actif : entrant refusé sauf services [${tcp[*]:-aucun}${udp[*]:+ udp:${udp[*]}}] depuis $ALLOW_FROM$([[ $ssh_on -eq 1 ]] && echo " et SSH depuis $ADMIN_NET")"
    info "Règles : $nftf | désactiver : systemctl disable --now lxc-hardening-firewall"

    # Ports en écoute non couverts -> seront bloqués
    local all blocked=()
    all="$(ss -Htln | awk '{print $4}' | while read -r x; do is_loopback "${x%:*}" || echo "${x##*:}"; done | sort -un)"
    for p in $all; do
        [[ " ${tcp[*]} " == *" $p "* || ( $ssh_on -eq 1 && "$p" == "$SSH_PORT_CUR" ) ]] || blocked+=("$p")
    done
    [[ ${#blocked[@]} -gt 0 ]] && warn "Ports en écoute désormais BLOQUÉS (service non reconnu) : ${blocked[*]} - à ouvrir si besoin avec --extra-ports"
    [[ $HAS_DOCKER -eq 1 ]] && warn "Docker : les ports publiés (-p) passent par la chaîne forward et contournent ce pare-feu ; publiez-les sur 127.0.0.1 ou filtrez côté Proxmox"
    return 0
}

# =============================================================================
#  ÉTAPE 7 - Services système, messagerie, journaux
# =============================================================================
step_07_services() {
    local purge=() p s
    for p in telnet inetutils-telnet rsh-client talk nis ftp xinetd avahi-daemon cups popularity-contest; do
        pkg_installed "$p" && purge+=("$p")
    done
    if [[ ${#purge[@]} -gt 0 ]]; then apt-get "${APT_OPTS[@]}" purge "${purge[@]}" >/dev/null; ok "Paquets supprimés : ${purge[*]}"; fi
    for s in rpcbind.socket rpcbind.service; do
        systemctl is-enabled --quiet "$s" 2>/dev/null && { systemctl disable --now "$s" >/dev/null 2>&1; ok "$s désactivé"; }
    done

    # Postfix des modèles Proxmox : messagerie locale uniquement
    if pkg_installed postfix; then
        if [[ "$(postconf -h inet_interfaces 2>/dev/null)" != "loopback-only" ]]; then
            postconf -e 'inet_interfaces = loopback-only'
            systemctl restart postfix 2>/dev/null || true
            ok "Postfix limité à la boucle locale (n'écoute plus sur le réseau)"
        else ok "Postfix déjà limité à la boucle locale"; fi
        postconf -e 'smtpd_banner = $myhostname ESMTP' 'disable_vrfy_command = yes' 2>/dev/null || true
    fi

    mkdir -p /etc/systemd/journald.conf.d
    printf '[Journal]\nStorage=persistent\nCompress=yes\nSystemMaxUse=200M\n' > /etc/systemd/journald.conf.d/60-lxc.conf
    systemctl restart systemd-journald
    ok "Journaux persistants (200 Mo max)"
    find /var/log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
    ok "Journaux non lisibles par les autres utilisateurs"
    timedatectl set-timezone Europe/Paris 2>/dev/null || true
}

# =============================================================================
#  ÉTAPE 8 - Apache + PHP
# =============================================================================
step_08_apache() {
    [[ -n "$UNIT_APACHE" ]] || { info "Apache absent : étape ignorée"; return 0; }
    local bak="$REPORT_DIR/apache2-avant"; cp -a /etc/apache2 "$bak"
    local phpbak="$REPORT_DIR/php-avant"; [[ -d /etc/php ]] && cp -a /etc/php "$phpbak"

    a2enmod -q headers >/dev/null
    local m dis=()
    for m in status info autoindex userdir cgi cgid dav dav_fs; do
        [[ -e /etc/apache2/mods-enabled/$m.load ]] && { a2dismod -q -f "$m" >/dev/null; dis+=("$m"); }
    done
    [[ ${#dis[@]} -gt 0 ]] && ok "Modules désactivés : ${dis[*]}"
    [[ " ${dis[*]} " == *" status "* && -n "$UNIT_CLOUDFLARED" ]] && \
        warn "mod_status était actif ALORS que cloudflared tourne ici : /server-status était visible depuis Internet (le tunnel arrive en 127.0.0.1)"

    cat > /etc/apache2/conf-available/zz-hardening.conf <<'EOF'
# Durcissement Apache (hardening-lxc.sh)
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Timeout 60
LimitRequestBody 67108864

<Directory /var/www/>
    Options -Indexes
</Directory>
<DirectoryMatch "/\.(git|svn|hg)">
    Require all denied
</DirectoryMatch>
<FilesMatch "^\.(env|ht.*|git.*)$|\.(bak|old|orig|save|swp|sql|log|dist)$">
    Require all denied
</FilesMatch>

# En-têtes ajoutés seulement si l'application ne les a pas déjà définis
Header setifempty X-Content-Type-Options "nosniff"
Header setifempty X-Frame-Options "SAMEORIGIN"
Header setifempty Referrer-Policy "strict-origin-when-cross-origin"
Header setifempty Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
Header always unset X-Powered-By
Header unset X-Powered-By
EOF
    a2enconf -q zz-hardening >/dev/null

    if [[ $CLOUDFLARE -eq 1 ]]; then
        a2enmod -q remoteip >/dev/null
        local proxies="127.0.0.1 ::1 ${TUNNEL_IPS//,/ }"
        cat > /etc/apache2/conf-available/zz-cloudflare-remoteip.conf <<EOF
# Vraie IP du visiteur derrière Cloudflare Tunnel (journaux, fail2ban, restrictions par IP)
RemoteIPHeader CF-Connecting-IP
RemoteIPInternalProxy ${proxies}
LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
EOF
        a2enconf -q zz-cloudflare-remoteip >/dev/null
        ok "Vraie IP client (CF-Connecting-IP) acceptée depuis : $proxies"
    fi

    # PHP (module Apache et/ou FPM)
    local d n=0
    for d in /etc/php/*/apache2/conf.d /etc/php/*/fpm/conf.d; do
        [[ -d "$d" ]] || continue
        cat > "$d/99-hardening.ini" <<'EOF'
; Durcissement PHP (hardening-lxc.sh)
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
allow_url_include = Off
session.use_strict_mode = 1
session.cookie_httponly = 1
session.cookie_samesite = Lax
EOF
        n=$((n+1))
    done
    [[ $n -gt 0 ]] && ok "PHP : version masquée, erreurs non affichées, cookies de session HttpOnly/SameSite"

    if apache2ctl configtest 2>"$REPORT_DIR/apache-configtest.txt"; then
        systemctl reload apache2 || systemctl restart apache2
        for s in $(systemctl list-units --type=service --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}'); do systemctl restart "$s"; done
        local code; code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/ || true)"
        if ! wait_healthy "$UNIT_APACHE" "${PORTS_BEFORE[$UNIT_APACHE]:-}" 15; then
            warn "Apache n'écoute plus sur ses ports après rechargement : restauration de la configuration précédente"
            rm -rf /etc/apache2 && cp -a "$bak" /etc/apache2
            [[ -d "$phpbak" ]] && { rm -rf /etc/php && cp -a "$phpbak" /etc/php; }
            systemctl restart apache2; return 1
        fi
        ok "Apache rechargé (réponse HTTP $code)"
        curl -sI --max-time 5 http://127.0.0.1/ > "$REPORT_DIR/entetes-http.txt" 2>/dev/null || true
    else
        warn "apache2ctl configtest en échec : restauration ($REPORT_DIR/apache-configtest.txt)"
        rm -rf /etc/apache2 && cp -a "$bak" /etc/apache2
        [[ -d "$phpbak" ]] && { rm -rf /etc/php && cp -a "$phpbak" /etc/php; }
        systemctl restart apache2; return 1
    fi
    [[ $CLOUDFLARE -eq 0 ]] && \
        info "Site publié via Cloudflare Tunnel ? Relancez avec --cloudflare --steps 8 pour journaliser la vraie IP des visiteurs"
    return 0
}

# =============================================================================
#  ÉTAPE 9 - FreshRSS
# =============================================================================
step_09_freshrss() {
    [[ -n "$FRESHRSS_DIR" ]] || { info "FreshRSS absent : étape ignorée"; return 0; }
    local dir="$FRESHRSS_DIR" webuser
    webuser="$(stat -c %U "$dir/data" 2>/dev/null || true)"
    [[ -z "$webuser" || "$webuser" == "root" ]] && webuser="www-data"
    ok "FreshRSS trouvé dans $dir"

    # Le DocumentRoot doit être le dossier public "p", jamais la racine (data/ contient la config et les comptes)
    local roots; roots="$(grep -rhoiE '^\s*DocumentRoot\s+\S+' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | tr -d '"' || true)"
    if grep -qxE "${dir}/?" <<<"$roots"; then
        warn "CRITIQUE : DocumentRoot = $dir -> data/ (mots de passe, config) est servi par Apache. Il doit pointer sur $dir/p"
    elif grep -qxE "${dir}/p/?" <<<"$roots"; then ok "DocumentRoot sur le dossier public $dir/p"
    else info "DocumentRoot de FreshRSS non trouvé dans sites-enabled (vérifiez qu'il pointe sur $dir/p)"; fi

    # Permissions recommandées par la documentation FreshRSS
    chown -R root:"$(id -gn "$webuser")" "$dir"
    chmod -R u=rwX,g=rX,o= "$dir"
    chmod -R g+w "$dir/data"
    [[ -d "$dir/extensions" ]] && chmod -R g-w "$dir/extensions"
    ok "Code en lecture seule pour $webuser, seul data/ est modifiable (installation d'extensions et mise à jour web désactivées)"

    local cfg="$dir/data/config.php"
    if [[ -f "$cfg" ]]; then
        grep -qE "'auth_type'\s*=>\s*'none'" "$cfg" && warn "CRITIQUE : FreshRSS sans authentification (auth_type = none) - à passer en 'form' dans la configuration"
        grep -qE "'allow_anonymous'\s*=>\s*true" "$cfg" && warn "FreshRSS : lecture anonyme autorisée (allow_anonymous)"
        grep -qE "'allow_robots'\s*=>\s*true" "$cfg" && info "FreshRSS : indexation par les moteurs autorisée (allow_robots)"
    fi
    if runuser -u "$webuser" -- php "$dir/cli/check.installation.php" >/dev/null 2>&1; then ok "Vérification d'installation FreshRSS : OK"
    else info "Point à vérifier : runuser -u $webuser -- php $dir/cli/check.installation.php"; fi
    return 0
}

# =============================================================================
#  ÉTAPE 10 - Vaultwarden (configuration)
# =============================================================================
vw_envfile() { systemctl show -p EnvironmentFiles --value "$UNIT_VW" 2>/dev/null | awk '{print $1}'; }

wait_healthy() {   # wait_healthy unité "ports attendus" délai
    local unit="$1" want="$2" timeout="${3:-40}" i now p okp
    for ((i=0; i<timeout; i++)); do
        sleep 1
        systemctl is-active --quiet "$unit" || continue
        if [[ -z "${want// /}" ]]; then [[ $i -ge 5 ]] && break || continue; fi
        now=" $(public_ports "$unit") "; okp=1
        for p in $want; do [[ "$now" == *" $p "* ]] || okp=0; done
        [[ $okp -eq 1 ]] && break
    done
    [[ $i -ge $timeout ]] && return 1
    sleep 3; systemctl is-active --quiet "$unit"
}

step_10_vaultwarden() {
    [[ -n "$UNIT_VW" ]] || { info "Vaultwarden absent : étape ignorée"; return 0; }
    local env; env="$(vw_envfile)"
    if [[ -z "$env" || ! -f "$env" ]]; then
        info "Pas de fichier d'environnement pour $UNIT_VW : configuration non modifiée"
    else
        cp -p "$env" "$REPORT_DIR/vaultwarden.env.avant"
        chmod 600 "$env"; chown root:root "$env"
        local changed=()
        if [[ $VW_KEEP_SIGNUPS -eq 0 && "$(get_env "$env" SIGNUPS_ALLOWED)" != "false" ]]; then
            set_kv "$env" SIGNUPS_ALLOWED false "="; changed+=("inscriptions fermées")
        fi
        [[ "$(get_env "$env" SHOW_PASSWORD_HINT)" != "false" ]] && { set_kv "$env" SHOW_PASSWORD_HINT false "="; changed+=("indices de mot de passe masqués"); }
        [[ "$(get_env "$env" PASSWORD_HINTS_ALLOWED)" != "false" ]] && { set_kv "$env" PASSWORD_HINTS_ALLOWED false "="; changed+=("indices désactivés"); }
        if [[ $CLOUDFLARE -eq 1 && "$(get_env "$env" IP_HEADER)" != "CF-Connecting-IP" ]]; then
            set_kv "$env" IP_HEADER CF-Connecting-IP "="; changed+=("vraie IP via CF-Connecting-IP")
        fi
        local tok; tok="$(get_env "$env" ADMIN_TOKEN)"
        if [[ -z "$tok" ]]; then ok "Page /admin désactivée (pas d'ADMIN_TOKEN)"
        elif [[ "$tok" != '$argon2'* ]]; then
            warn "Vaultwarden : ADMIN_TOKEN en clair. Générez un hash : $(command -v vaultwarden || echo vaultwarden) hash  puis remplacez la valeur (entre apostrophes)"
        else ok "ADMIN_TOKEN haché en Argon2"; fi

        local data vwd; data="$(get_env "$env" DATA_FOLDER)"
        vwd="$(systemctl show -p WorkingDirectory --value "$UNIT_VW")"
        [[ -z "$data" ]] && data="$vwd/data"
        [[ "$data" == /* ]] || data="$vwd/${data#./}"
        if [[ -f "$data/config.json" ]]; then
            grep -qE '"signups_allowed"\s*:\s*true' "$data/config.json" && \
                warn "Vaultwarden : $data/config.json (page /admin) autorise les inscriptions et PRIME sur le .env : à corriger dans /admin"
        fi
        if [[ ${#changed[@]} -gt 0 ]]; then
            systemctl restart "$UNIT_VW"
            if wait_healthy "$UNIT_VW" "${PORTS_BEFORE[$UNIT_VW]:-}" 30; then ok "Vaultwarden redémarré : ${changed[*]}"
            else
                cp -p "$REPORT_DIR/vaultwarden.env.avant" "$env"; systemctl restart "$UNIT_VW"
                echo "Vaultwarden ne redémarre pas avec la nouvelle configuration : .env restauré"; return 1
            fi
        else ok "Configuration Vaultwarden déjà conforme"; fi
    fi
    [[ -n "$UNIT_CLOUDFLARED" ]] || info "Rappel : la 2FA de chaque compte et Cloudflare Access protègent l'accès ; la sauvegarde de $(systemctl show -p WorkingDirectory --value "$UNIT_VW")/data est vitale"
    return 0
}

# =============================================================================
#  ÉTAPE 11 - Sandbox systemd + compte dédié
# =============================================================================
SANDBOX_FULL='NoNewPrivileges=yes
UMask=0027
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
CapabilityBoundingSet='
# Variante sans espace de noms de montage (conteneur sans nesting)
SANDBOX_LIGHT='NoNewPrivileges=yes
UMask=0027
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
CapabilityBoundingSet='

sandbox_unit() {   # sandbox_unit unité utilisateur "dossiers en écriture" [fichiers à rendre lisibles]
    local unit="$1" svcuser="$2" rwdirs="$3" readable="${4:-}"
    local dropdir="/etc/systemd/system/${unit}.d" drop wd cur d level
    drop="$dropdir/60-hardening.conf"
    wd="$(systemctl show -p WorkingDirectory --value "$unit")"
    cur="$(systemctl show -p User --value "$unit")"; cur="${cur:-root}"
    local want="${PORTS_BEFORE[$unit]:-}"
    if [[ -f "$drop" ]]; then ok "$unit : déjà durci ($drop)"; return 0; fi
    for d in $rwdirs; do
        case "$d" in
            /|/bin*|/boot*|/dev*|/etc*|/lib*|/proc*|/sbin*|/sys*|/usr|/usr/bin*|/usr/sbin*|/usr/lib*|/var|/var/lib|/opt|/home|/root|/tmp)
                warn "$unit : dossier de données suspect ($d), sandbox non appliquée par sécurité"; return 0 ;;
        esac
        [[ "$d" == /*/* ]] || { warn "$unit : chemin de données invalide ($d), sandbox non appliquée"; return 0; }
    done

    # Ports < 1024 : un compte non root ne peut pas les ouvrir
    local p low=0; for p in $want; do [[ $p -lt 1024 ]] && low=1; done

    local switch=0
    if [[ "$cur" == "root" && $low -eq 0 ]]; then
        switch=1
        id "$svcuser" >/dev/null 2>&1 || useradd --system --user-group --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin "$svcuser"
    else svcuser="$cur"; fi

    # État initial pour le retour arrière
    local restore=() f own mode
    for d in $rwdirs; do mkdir -p "$d"; restore+=("$d|$(stat -c %U:%G "$d")"); done
    for f in $readable; do [[ -e "$f" ]] && restore+=("$f|$(stat -c %U:%G "$f")|$(stat -c %a "$f")"); done
    local wd_grp=""; [[ -n "$wd" && -d "$wd" ]] && wd_grp="$(stat -c %G "$wd")"

    if [[ $switch -eq 1 ]]; then
        for d in $rwdirs; do chown -R "$svcuser:$svcuser" "$d"; done
        for f in $readable; do [[ -e "$f" ]] && { chgrp "$svcuser" "$f"; chmod g+rX "$f"; }; done
        # Le code doit rester lisible par le compte de service
        if [[ -n "$wd" && -d "$wd" ]] && [[ -n "$(find "$wd" -maxdepth 3 ! -perm -o=r -not -path '*/data/*' -print -quit 2>/dev/null)" ]]; then
            chgrp -R "$svcuser" "$wd"; chmod -R g+rX "$wd"
            for d in $rwdirs; do chown -R "$svcuser:$svcuser" "$d"; done
        fi
    fi

    mkdir -p "$dropdir"
    for level in full light; do
        {
            echo "# Durcissement $unit (hardening-lxc.sh) - niveau $level"
            echo "# Annuler : rm $drop && systemctl daemon-reload && systemctl restart $unit"
            echo "[Service]"
            if [[ $switch -eq 1 ]]; then
                echo "User=$svcuser"; echo "Group=$svcuser"
                # '+' = exécuté en root : remet les droits après une mise à jour faite en root
                echo "ExecStartPre=-+$(command -v chown) -R $svcuser:$svcuser $rwdirs"
            fi
            if [[ "$level" == full ]]; then echo "$SANDBOX_FULL"; echo "ReadWritePaths=$(for d in $rwdirs; do printf -- '-%s ' "$d"; done)"
            else echo "$SANDBOX_LIGHT"; fi
            [[ $switch -eq 0 && $low -eq 1 ]] && echo "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID"
        } > "$drop"
        systemctl daemon-reload
        systemctl restart "$unit" 2>/dev/null || true
        if wait_healthy "$unit" "$want" 60; then
            ok "$unit : $([[ $switch -eq 1 ]] && echo "compte dédié '$svcuser', " )sandbox $([[ $level == full ]] && echo complète || echo "allégée (pas d'espaces de noms de montage dans ce conteneur)")"
            info "   score : $(systemd-analyze security "$unit" --no-pager 2>/dev/null | tail -1 | sed 's/.*exposure level for [^:]*: //' || echo '?')"
            return 0
        fi
        info "$unit ne démarre pas en sandbox $level$( [[ $level == full ]] && echo ', essai en version allégée')"
        journalctl -u "$unit" -n 20 --no-pager > "$REPORT_DIR/echec-$unit-$level.txt" 2>&1 || true
    done

    # Retour arrière complet
    rm -f "$drop"; rmdir "$dropdir" 2>/dev/null || true
    local e
    for e in "${restore[@]}"; do
        IFS='|' read -r d own mode <<<"$e"
        if [[ -n "${mode:-}" ]]; then chown "$own" "$d"; chmod "$mode" "$d"; else chown -R "$own" "$d"; fi
    done
    [[ -n "$wd_grp" ]] && chgrp -R "$wd_grp" "$wd" 2>/dev/null || true
    systemctl daemon-reload; systemctl restart "$unit" || true
    warn "$unit : sandbox impossible, configuration d'origine restaurée (journaux : $REPORT_DIR/echec-$unit-*.txt)"
    return 0
}

step_11_sandbox() {
    if [[ $NO_SANDBOX -eq 1 ]]; then info "--no-sandbox : étape ignorée"; return 0; fi
    local found=0 wd

    if [[ -n "$UNIT_KUMA" ]]; then
        found=1
        wd="$(systemctl show -p WorkingDirectory --value "$UNIT_KUMA")"; wd="${wd:-/opt/uptime-kuma}"
        # Ping sans privilège (sockets ICMP), indispensable aux sondes ping hors root
        echo 'net.ipv4.ping_group_range = 0 2147483647' > /etc/sysctl.d/61-ping-unprivileged.conf
        sysctl -qw 'net.ipv4.ping_group_range=0 2147483647' 2>/dev/null || info "ping_group_range non modifiable : les sondes ping d'Uptime Kuma risquent d'échouer"
        sandbox_unit "$UNIT_KUMA" "uptime-kuma" "$wd/data"
        if command -v python3 >/dev/null && [[ -f "$wd/data/kuma.db" ]]; then
            local da; da="$(python3 -c "import sqlite3,sys; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); r=c.execute(\"select value from setting where key='disableAuth'\").fetchone(); print(r[0] if r else '')" "$wd/data/kuma.db" 2>/dev/null || true)"
            [[ "$da" == "true" ]] && warn "CRITIQUE : Uptime Kuma a l'authentification DÉSACTIVÉE (Paramètres > Sécurité)"
        fi
        info "Uptime Kuma : activez la 2FA (Paramètres > Sécurité). Ne montez jamais /var/run/docker.sock dans un service exposé."
    fi

    if [[ -n "$UNIT_MYSPEED" ]]; then
        found=1
        wd="$(systemctl show -p WorkingDirectory --value "$UNIT_MYSPEED")"; wd="${wd:-/opt/myspeed}"
        sandbox_unit "$UNIT_MYSPEED" "myspeed" "$wd/data $wd/bin"
        info "MySpeed : sans mot de passe par défaut, n'importe qui sur le réseau peut modifier la config -> Paramètres > Mot de passe"
    fi

    if [[ -n "$UNIT_VW" ]]; then
        found=1
        local env data tls certs=""
        wd="$(systemctl show -p WorkingDirectory --value "$UNIT_VW")"; wd="${wd:-/opt/vaultwarden}"
        env="$(vw_envfile)"
        data=""; tls=""
        if [[ -n "$env" && -f "$env" ]]; then data="$(get_env "$env" DATA_FOLDER)"; tls="$(get_env "$env" ROCKET_TLS)"; fi
        data="${data:-$wd/data}"; [[ "$data" == /* ]] || data="$wd/${data#./}"
        if [[ -n "$tls" ]]; then
            local c; for c in $(grep -oE '/[^"'"'"',}[:space:]]+' <<<"$tls" || true); do
                certs+="$(dirname "$c") $c "
            done
            certs="$(tr ' ' '\n' <<<"$certs" | awk 'NF && !seen[$0]++' | tr '\n' ' ')"
        fi
        sandbox_unit "$UNIT_VW" "vaultwarden" "$data" "$certs"
    fi
    [[ $found -eq 0 ]] && info "Aucun service Node/Rust connu (Vaultwarden, Uptime Kuma, MySpeed) dans ce conteneur"
    return 0
}

# =============================================================================
#  ÉTAPE 12 - Docker
# =============================================================================
step_12_docker() {
    [[ $HAS_DOCKER -eq 1 ]] || { info "Docker absent : étape ignorée"; return 0; }
    local c out="$REPORT_DIR/docker-conteneurs.txt"
    : > "$out"
    for c in $(docker ps -q 2>/dev/null); do
        docker inspect -f '{{.Name}}|{{.Config.Image}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{range .Mounts}}{{.Source}} {{end}}|{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}|{{.Config.User}}' "$c" >> "$out"
    done
    local n=0 name img priv net mounts ports user
    while IFS='|' read -r name img priv net mounts ports user; do
        n=$((n+1)); name="${name#/}"
        [[ "$priv" == "true" ]] && warn "Docker $name : conteneur PRIVILÉGIÉ"
        [[ "$net" == "host" ]] && warn "Docker $name : réseau 'host' (partage la pile réseau du conteneur LXC)"
        [[ "$mounts" == *docker.sock* ]] && warn "Docker $name : monte docker.sock (= root sur tout Docker). Si possible en lecture seule via un proxy (tecnativa/docker-socket-proxy)"
        [[ "$ports" =~ (^|[[:space:]])(0\.0\.0\.0|::|):[0-9]+ ]] && info "Docker $name : ports publiés sur toutes les interfaces ($ports) - non filtrés par le pare-feu du conteneur"
        [[ -z "$user" || "$user" == "root" || "$user" == "0" ]] && info "Docker $name ($img) tourne en root dans son conteneur"
    done < "$out"
    ok "$n conteneur(s) Docker analysé(s) : $out"

    if [[ $DOCKER_HARDEN -eq 1 ]]; then
        local dj=/etc/docker/daemon.json; mkdir -p /etc/docker
        [[ -f "$dj" ]] && cp -p "$dj" "$REPORT_DIR/daemon.json.avant"
        python3 - "$dj" <<'PY'
import json, os, sys
p = sys.argv[1]
d = json.load(open(p)) if os.path.exists(p) and os.path.getsize(p) else {}
d.setdefault("log-driver", "json-file")
d.setdefault("log-opts", {"max-size": "10m", "max-file": "3"})
d["no-new-privileges"] = True
d["live-restore"] = True
d["userland-proxy"] = False
json.dump(d, open(p, "w"), indent=2)
PY
        if systemctl restart docker && sleep 5 && docker info >/dev/null 2>&1; then ok "daemon.json durci (no-new-privileges, rotation des journaux, live-restore)"
        else
            [[ -f "$REPORT_DIR/daemon.json.avant" ]] && cp -p "$REPORT_DIR/daemon.json.avant" "$dj" || rm -f "$dj"
            systemctl restart docker; echo "Docker ne redémarre pas : daemon.json restauré"; return 1
        fi
    else
        info "Durcissement du démon Docker non appliqué (redémarre les conteneurs) : relancez avec --docker-harden --steps 12"
    fi
    host_todo "Docker dans un LXC demande nesting=1 et keyctl=1 : à réserver à ce conteneur, jamais en privilégié"
}

# =============================================================================
#  ÉTAPE 13 - Vérifications et recommandations
# =============================================================================
step_13_verifications() {
    echo "  --- Services"
    local u
    for u in $UNIT_APACHE $UNIT_VW $UNIT_KUMA $UNIT_MYSPEED $UNIT_CLOUDFLARED lxc-hardening-firewall.service ssh.service unattended-upgrades.service; do
        unit_exists "$u" || continue
        printf '      %-34s %-10s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)" \
            "$( [[ -f /etc/systemd/system/$u.d/60-hardening.conf ]] && echo "utilisateur : $(systemctl show -p User --value "$u")" )"
    done
    echo "  --- Ports en écoute (hors boucle locale)"
    ss -Htlnp | awk '{print $4, $NF}' | while read -r a pr; do is_loopback "${a%:*}" || printf '      %-24s %s\n' "$a" "$(grep -oE '"[^"]+"' <<<"$pr" | head -1)"; done
    ss -tulpn > "$REPORT_DIR/ports-apres.txt"

    if [[ $NO_AUDIT -eq 0 ]]; then
        pkg_installed lynis || apt_install lynis
        info "Audit Lynis final..."
        lynis audit system --quiet --no-colors --logfile "$REPORT_DIR/lynis-apres.log" \
            --report-file "$REPORT_DIR/lynis-apres.dat" >/dev/null 2>&1 || true
        local av ap; ap="$(lynis_index "$REPORT_DIR/lynis-apres.dat")"; av="$(lynis_index "$REPORT_DIR/lynis-avant.dat")"
        ok "Indice Lynis : AVANT ${av:-?}/100 -> APRÈS ${ap:-?}/100 (en conteneur, les tests noyau/démarrage sont sans objet)"
    fi

    {
        echo "Hors de portée du conteneur - à faire sur l'hôte Proxmox :"
        echo " - pct config <CTID> : unprivileged: 1, pas de 'lxc.apparmor.profile: unconfined' ni 'lxc.cap.drop:' vide"
        echo " - nesting=1 seulement si nécessaire (systemd récent, Docker) ; keyctl=1 seulement pour Docker"
        echo " - pct set <CTID> --protection 1   (pas de suppression accidentelle)"
        echo " - Sauvegardes vzdump planifiées + test de restauration"
        echo " - Lancer ce script avec --host-audit sur l'hôte pour un état de tous les conteneurs"
    } >> "$HOST_FILE"
    return 0
}

# =============================================================================
#  Exécution
# =============================================================================
echo "${C_CYAN}hardening-lxc.sh v$VERSION - $(hostname) - $PRETTY_NAME${C_RST}"
echo "  Étapes       : ${STEPS[*]}"
echo "  Services     : ${UNIT_APACHE:+Apache }${FRESHRSS_DIR:+FreshRSS }${UNIT_VW:+Vaultwarden }${UNIT_KUMA:+Uptime-Kuma }${UNIT_MYSPEED:+MySpeed }${UNIT_CLOUDFLARED:+cloudflared }$([[ $HAS_DOCKER -eq 1 ]] && echo Docker)"
echo "  Autorisés    : services <- $ALLOW_FROM ; SSH <- $ADMIN_NET"
echo "  Rapports     : $REPORT_DIR"
if [[ $ASSUME_YES -eq 0 && -t 0 ]]; then
    read -r -p "Snapshot fait (pct snapshot <CTID> avant-hardening) ? Continuer [o/N] " rep
    [[ "$rep" =~ ^[oOyY]$ ]] || { echo "Abandon."; exit 0; }
fi

run_step 0  step_00_detection      "Détection et audit initial"
run_step 1  step_01_sauvegarde     "Sauvegarde et prérequis"
run_step 2  step_02_mises_a_jour   "Mises à jour"
run_step 3  step_03_comptes        "Comptes et sessions"
run_step 4  step_04_ssh            "SSH"
run_step 5  step_05_reseau         "Réseau du conteneur"
run_step 6  step_06_parefeu        "Pare-feu nftables"
run_step 7  step_07_services       "Services système et journaux"
run_step 8  step_08_apache         "Apache + PHP"
run_step 9  step_09_freshrss       "FreshRSS"
run_step 10 step_10_vaultwarden    "Vaultwarden"
run_step 11 step_11_sandbox        "Sandbox systemd des services"
run_step 12 step_12_docker         "Docker"
run_step 13 step_13_verifications  "Vérifications"

echo
echo "${C_CYAN}===== Bilan =====${C_RST}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "${C_RED}Étape(s) en échec :${C_RST}"; printf '   - %s\n' "${FAILED[@]}"; printf '%s\n' "${FAILED[@]}" > "$REPORT_DIR/echecs.txt"
else echo "${C_GREEN}Toutes les étapes demandées se sont terminées sans erreur.${C_RST}"; fi
[[ -s "$WARN_FILE" ]] && { echo "${C_YEL}Points d'attention :${C_RST}"; sed 's/^/   - /' "$WARN_FILE"; }
if [[ -s "$HOST_FILE" ]]; then echo "${C_YEL}Sur l'hôte Proxmox :${C_RST}"; sort -u "$HOST_FILE" | sed 's/^/   - /'; fi
echo
echo "Testez vos services depuis le navigateur (LAN et via le tunnel) avant de supprimer le snapshot."
echo "Journal complet : $LOG"
