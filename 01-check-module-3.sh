#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"

[[ -f "$ENV_FILE" ]] || {
    echo "ERROR: $ENV_FILE not found" >&2
    exit 1
}

# shellcheck disable=SC1090
source "$ENV_FILE"

required_variables=(
    HQ_SRV_IP BR_SRV_IP LINUX_SSH_USER LINUX_SSH_PASSWORD LINUX_SSH_PORT
    ISP_IP ISP_SSH_USER ISP_SSH_PASSWORD ISP_SSH_PORT
    HQ_RTR_SSH_HOST BR_RTR_SSH_HOST HQ_RTR_WAN_IP BR_RTR_WAN_IP
    ROUTER_SSH_USER ROUTER_SSH_PASSWORD ROUTER_SSH_PORT
    DOMAIN_FQDN CSV_FILE WEB_DOMAIN DOCKER_DOMAIN CERT_DAYS CA_COMMON_NAME
    AUTH_USER AUTH_PASSWORD IPSEC_PROFILE CRYPTO_MAP VPN_FILTER_MAP
    TUNNEL_INTERFACE FIREWALL_MAP WAN_INTERFACE ALLOWED_TCP_PORTS
    CUPS_SERVER_PORT CUPS_SERVER_QUEUE CUPS_CLIENT_QUEUE
    LOG_ROOT LOG_FILE_NAME LOG_SERVER_PORT LOG_PROTOCOL LOG_HOSTS ROTATE_SIZE
    MON_DOMAIN GRAFANA_PORT PROMETHEUS_PORT NODE_EXPORTER_PORT
    GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD ANSIBLE_DIR
    INVENTORY_PLAYBOOK INVENTORY_REPORT_DIR HQ_CLI_IP
    AUTO_INSTALL
)

for variable_name in "${required_variables[@]}"; do
    [[ -n "${!variable_name:-}" ]] || {
        echo "ERROR: $variable_name is empty in $ENV_FILE" >&2
        exit 1
    }
done

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_BOLD=$'\033[1m'
else
    C_RESET=
    C_RED=
    C_GREEN=
    C_YELLOW=
    C_BLUE=
    C_BOLD=
fi

declare -A RESULT_SCORE RESULT_TITLE RESULT_DETAIL
TOTAL_HALF_POINTS=0
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

log() {
    printf '%s[check]%s %s\n' "$C_BLUE" "$C_RESET" "$*"
}

warn() {
    printf '%sWARNING:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2
}

set_result() {
    local number="$1"
    local score="$2"
    local title="$3"
    local detail="$4"

    RESULT_SCORE["$number"]="$score"
    RESULT_TITLE["$number"]="$title"
    RESULT_DETAIL["$number"]="$detail"

    case "$score" in
        1) TOTAL_HALF_POINTS=$((TOTAL_HALF_POINTS + 2)) ;;
        0.5) TOTAL_HALF_POINTS=$((TOTAL_HALF_POINTS + 1)) ;;
    esac
}

contains() {
    grep -Fq -- "$2" <<< "$1"
}

count_matches() {
    grep -Eo -- "$2" <<< "$1" 2>/dev/null | wc -l
}

remote_script() {
    local host="$1"
    local port="$2"
    local user="$3"
    local password="$4"
    local privileged="$5"
    local script="$6"
    local remote_shell="bash -s"
    local output
    local status

    if [[ "$privileged" == yes && "$user" != root ]]; then
        remote_shell="sudo -n bash -s"
    fi

    output="$(
        SSHPASS="$password" sshpass -e ssh \
            -p "$port" \
            -o BatchMode=no \
            -o ConnectTimeout=8 \
            -o ConnectionAttempts=1 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$user@$host" "$remote_shell" <<< "$script"
    )"
    status=$?

    if ((status != 0)) && [[ "$privileged" == yes && "$user" != root ]]; then
        output="$(
            {
                printf '%s\n' "$password"
                printf '%s\n' "$script"
            } |
                SSHPASS="$password" sshpass -e ssh \
                    -p "$port" \
                    -o BatchMode=no \
                    -o ConnectTimeout=8 \
                    -o ConnectionAttempts=1 \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o LogLevel=ERROR \
                    "$user@$host" "sudo -S -p '' bash -s"
        )"
        status=$?
    fi

    printf '%s\n' "$output"
    return "$status"
}

linux_remote() {
    remote_script \
        "$1" "$LINUX_SSH_PORT" \
        "$LINUX_SSH_USER" "$LINUX_SSH_PASSWORD" yes "$2"
}

isp_remote() {
    remote_script \
        "$ISP_IP" "$ISP_SSH_PORT" \
        "$ISP_SSH_USER" "$ISP_SSH_PASSWORD" yes "$1"
}

install_dependencies() {
    local missing=()
    local command_name

    declare -A package_for=(
        [ssh]=openssh-clients
        [sshpass]=sshpass
        [expect]=expect
        [curl]=curl
        [openssl]=openssl
        [kinit]=krb5-clients
    )

    for command_name in "${!package_for[@]}"; do
        command -v "$command_name" >/dev/null 2>&1 ||
            missing+=("${package_for[$command_name]}")
    done

    ((${#missing[@]} == 0)) && return 0
    [[ "$AUTO_INSTALL" == yes ]] || {
        warn "Missing diagnostic packages: ${missing[*]}"
        return 1
    }
    [[ $EUID -eq 0 ]] || {
        warn "Run as root to install: ${missing[*]}"
        return 1
    }

    log "Installing diagnostic packages: ${missing[*]}"
    apt-get update && apt-get install -y "${missing[@]}"
}

create_router_expect() {
    cat > "$TMP_DIR/router-command.exp" <<'EXPECT'
#!/usr/bin/expect -f
set timeout 25
match_max 500000

set host [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set command [lindex $argv 3]
set password $env(ROUTER_CHECK_PASSWORD)
set enable_password $env(ROUTER_CHECK_ENABLE_PASSWORD)
set prompt_re {(?i)[a-z0-9_.-]+(\([^)\r\n]+\))*[>#][ \t]*}

proc fail {message} {
    puts stderr "ERROR: $message"
    exit 1
}

proc wait_prompt {} {
    global prompt_re
    expect {
        -re {\x1b\[6n} {
            send -- "\033\[24;86R"
            exp_continue
        }
        -re {(?i)are you sure you want to continue connecting.*} {
            send -- "yes\r"
            exp_continue
        }
        -re $prompt_re { return }
        -re {(?i)permission denied} { fail "router authentication failed" }
        timeout { fail "router prompt timeout" }
        eof { fail "router connection closed" }
    }
}

proc wait_output {} {
    global prompt_re
    expect {
        -re {\x1b\[6n} {
            send -- "\033\[24;86R"
            exp_continue
        }
        -re {(?i)(--more--|more:|press any key|press space)} {
            send -- " "
            exp_continue
        }
        -re $prompt_re { return }
        timeout { fail "router command timeout" }
        eof { fail "router connection closed during command" }
    }
}

set env(SSHPASS) $password
spawn sshpass -e ssh -tt \
    -p $port \
    -o ConnectTimeout=8 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -- "$user@$host"

wait_prompt
send -- "enable\r"
expect {
    -re {(?i)password[[:space:]]*:[[:space:]]*} {
        if {$enable_password eq ""} {
            fail "enable password requested but not configured"
        }
        send -- "$enable_password\r"
        wait_prompt
    }
    -re $prompt_re {}
    timeout { fail "enable timeout" }
}

send -- "terminal length 0\r"
wait_prompt
send -- "$command\r"
wait_output
send -- "exit\r"
expect eof
EXPECT
    chmod 0700 "$TMP_DIR/router-command.exp"
}

router_command() {
    ROUTER_CHECK_PASSWORD="$ROUTER_SSH_PASSWORD" \
        ROUTER_CHECK_ENABLE_PASSWORD="${ROUTER_ENABLE_PASSWORD:-}" \
        "$TMP_DIR/router-command.exp" \
        "$1" "$ROUTER_SSH_PORT" "$ROUTER_SSH_USER" "$2" 2>/dev/null |
        sed -E $'s/\033\\[[0-9;?]*[[:alpha:]]//g'
}

check_1_users() {
    local title="Импорт пользователей из users.csv"
    local output
    local total=0
    local found=0
    local first_user=""
    local password_b64=""
    local password=""
    local visible=no
    local auth=no
    local principal

    output="$(linux_remote "$BR_SRV_IP" "
csv='$CSV_FILE'
if [[ ! -f \"\$csv\" ]]; then
    csv=\$(find /iso /mnt -maxdepth 2 -type f -iname 'users.csv' -print -quit 2>/dev/null)
fi
[[ -f \"\$csv\" ]] || exit 1
total=0
found=0
first_user=
first_password=
while IFS=';' read -r firstname lastname role phone ou street zip city country password; do
    firstname=\${firstname//$'\r'/}
    lastname=\${lastname//$'\r'/}
    password=\$(printf '%s' \"\$password\" | tr -d '[:space:]')
    [[ -n \"\$firstname\" && -n \"\$lastname\" && -n \"\$password\" ]] || continue
    username=\"\$firstname.\$lastname\"
    total=\$((total + 1))
    samba-tool user show \"\$username\" >/dev/null 2>&1 && found=\$((found + 1))
    if [[ -z \"\$first_user\" ]]; then
        first_user=\"\$username\"
        first_password=\"\$password\"
    fi
done < <(tail -n +2 \"\$csv\")
printf 'TOTAL:%s\nFOUND:%s\nFIRST:%s\nPASS64:%s\n' \
    \"\$total\" \"\$found\" \"\$first_user\" \
    \"\$(printf '%s' \"\$first_password\" | base64 | tr -d '\n')\"
" 2>/dev/null)" || true

    total="$(awk -F: '/^TOTAL:/ {print $2; exit}' <<< "$output")"
    found="$(awk -F: '/^FOUND:/ {print $2; exit}' <<< "$output")"
    first_user="$(awk -F: '/^FIRST:/ {print $2; exit}' <<< "$output")"
    password_b64="$(awk -F: '/^PASS64:/ {print $2; exit}' <<< "$output")"
    total="${total:-0}"
    found="${found:-0}"

    if [[ -n "$first_user" ]] &&
        { getent passwd "$first_user" >/dev/null 2>&1 ||
          getent passwd "$first_user@$DOMAIN_FQDN" >/dev/null 2>&1; }; then
        visible=yes
    fi

    if [[ -n "$password_b64" ]]; then
        password="$(printf '%s' "$password_b64" | base64 -d 2>/dev/null || true)"
        principal="${first_user}@${DOMAIN_FQDN^^}"
        if [[ -n "$password" ]] &&
            KRB5CCNAME="FILE:$TMP_DIR/krb5cc_import" \
                kinit "$principal" <<< "$password" >/dev/null 2>&1; then
            auth=yes
        fi
        rm -f -- "$TMP_DIR/krb5cc_import"
    fi

    if ((total > 0 && found == total)) && [[ "$visible$auth" == yesyes ]]; then
        set_result 1 1 "$title" "$found пользователей импортированы, NSS и Kerberos-вход работают"
    elif ((found > 0)); then
        set_result 1 0.5 "$title" "Найдено $found из $total пользователей, вход подтверждён не полностью"
    else
        set_result 1 0 "$title" "Импортированные пользователи не обнаружены"
    fi
}

check_2_pki() {
    local title="Центр сертификации и HTTPS"
    local hq_output
    local served_cert="$TMP_DIR/served-web.crt"
    local cert_output=""
    local web_code=000
    local docker_code=000
    local ca_ok=no
    local cert_ok=no
    local trust_ok=no
    local gost=no

    hq_output="$(linux_remote "$HQ_SRV_IP" "
test -s /root/au-team-ca/ca.crt && echo CA:yes
test -s /root/au-team-ca/ca.key && echo CAKEY:yes
test -s /root/au-team-ca/web.crt && echo CERT:yes
openssl verify -CAfile /root/au-team-ca/ca.crt /root/au-team-ca/web.crt 2>/dev/null || true
openssl x509 -in /root/au-team-ca/web.crt -noout -checkend 0 &&
    echo VALID_NOW:yes
if ! openssl x509 -in /root/au-team-ca/web.crt \
    -noout -checkend $(((CERT_DAYS + 1) * 86400)); then
    echo VALIDITY:yes
fi
" 2>/dev/null)" || true

    contains "$hq_output" "CA:yes" &&
        contains "$hq_output" "CAKEY:yes" &&
        contains "$hq_output" "web.crt: OK" &&
        contains "$hq_output" "VALID_NOW:yes" &&
        contains "$hq_output" "VALIDITY:yes" && ca_ok=yes

    openssl s_client \
        -connect "$WEB_DOMAIN:443" \
        -servername "$WEB_DOMAIN" \
        -showcerts </dev/null 2>/dev/null |
        awk '
            /-----BEGIN CERTIFICATE-----/ {capture=1}
            capture {print}
            /-----END CERTIFICATE-----/ {exit}
        ' > "$served_cert"

    if [[ -s "$served_cert" ]]; then
        cert_output="$(
            openssl x509 -in "$served_cert" \
                -noout -text -dates -ext subjectAltName 2>/dev/null || true
        )"
        contains "$cert_output" "DNS:$WEB_DOMAIN" &&
            contains "$cert_output" "DNS:$DOCKER_DOMAIN" &&
            openssl x509 -in "$served_cert" -noout -checkend 0 \
                >/dev/null 2>&1 &&
            cert_ok=yes
        grep -Eqi '(gost|id-tc26|1\.2\.643\.)' <<< "$cert_output" && gost=yes
    fi

    web_code="$(curl -sS --connect-timeout 5 --max-time 15 \
        -o /dev/null -w '%{http_code}' \
        -u "$AUTH_USER:$AUTH_PASSWORD" "https://$WEB_DOMAIN/" 2>/dev/null || true)"
    docker_code="$(curl -sS --connect-timeout 5 --max-time 15 \
        -o /dev/null -w '%{http_code}' "https://$DOCKER_DOMAIN/" 2>/dev/null || true)"
    web_code="${web_code:-000}"
    docker_code="${docker_code:-000}"
    if [[ "$web_code" =~ ^(2|3)[0-9][0-9]$ &&
        "$docker_code" =~ ^(2|3)[0-9][0-9]$ ]]; then
        trust_ok=yes
    fi

    if [[ "$ca_ok$cert_ok$trust_ok$gost" == yesyesyesyes ]]; then
        set_result 2 1 "$title" "GOST-сертификат установлен, оба HTTPS-сайта доверены"
    elif [[ "$ca_ok$cert_ok$trust_ok" == yesyesyes ]]; then
        set_result 2 0.5 "$title" "PKI и доверенный HTTPS работают, но сертификат использует не GOST"
    else
        set_result 2 0 "$title" \
            "PKI: $ca_ok, сертификат: $cert_ok, HTTPS: web=$web_code docker=$docker_code"
    fi
}

ipsec_configured() {
    local config="$1"
    local peer="$2"

    contains "$config" "crypto-ipsec ike enable" &&
        contains "$config" "crypto-ipsec profile $IPSEC_PROFILE ike-v2" &&
        contains "$config" "proposal aes256-sha256-modp2048" &&
        contains "$config" "protocol esp" &&
        contains "$config" "match peer $peer" &&
        contains "$config" "set crypto-ipsec profile $IPSEC_PROFILE"
}

sa_active() {
    local output="$1"
    local peer="$2"

    contains "$output" "$peer" &&
        grep -Eqi '(established|active|installed|ready|up|spi|child_sa|ike_sa)' <<< "$output" &&
        ! grep -Eqi '(no security associations|not established|down|failed)' <<< "$output"
}

check_3_ipsec() {
    local title="Зашифрованный туннель между маршрутизаторами"
    local hq_config="$1"
    local br_config="$2"
    local hq_sa="$3"
    local br_sa="$4"
    local hq_ok=no
    local br_ok=no
    local hq_active=no
    local br_active=no

    ipsec_configured "$hq_config" "$BR_RTR_WAN_IP" && hq_ok=yes
    ipsec_configured "$br_config" "$HQ_RTR_WAN_IP" && br_ok=yes
    sa_active "$hq_sa" "$BR_RTR_WAN_IP" && hq_active=yes
    sa_active "$br_sa" "$HQ_RTR_WAN_IP" && br_active=yes

    if [[ "$hq_ok$br_ok$hq_active$br_active" == yesyesyesyes ]]; then
        set_result 3 1 "$title" "IPsec настроен с обеих сторон, SA активны"
    elif [[ "$hq_ok" == yes || "$br_ok" == yes ]]; then
        set_result 3 0.5 "$title" "IPsec сконфигурирован не полностью или SA не установлены"
    else
        set_result 3 0 "$title" "Конфигурация IPsec не обнаружена"
    fi
}

firewall_router_ok() {
    local config="$1"
    local wan_block
    local tunnel_block

    contains "$config" "filter-map ipv4 $FIREWALL_MAP" || return 1
    grep -Eqi 'match tcp any (any eq|eq) (80|http)([[:space:]]|$)' \
        <<< "$config" || return 1
    grep -Eqi 'match tcp any (any eq|eq) (443|https)([[:space:]]|$)' \
        <<< "$config" || return 1
    grep -Eqi 'match (tcp|udp) any (any eq|eq) (53|dns|domain)([[:space:]]|$)' \
        <<< "$config" || return 1
    grep -Eqi 'match udp any (any eq|eq) (123|ntp)([[:space:]]|$)' \
        <<< "$config" || return 1
    contains "$config" "match icmp any any" || return 1

    wan_block="$(
        awk -v interface_name="$WAN_INTERFACE" '
            $0 ~ "^interface[[:space:]]+" interface_name "[[:space:]]*$" {
                inside = 1
                next
            }
            inside && /^interface[[:space:]]+/ {
                exit
            }
            inside && /^!/ {
                exit
            }
            inside {
                print
            }
        ' <<< "$config"
    )"
    grep -Eq "set filter-map in ${FIREWALL_MAP}([[:space:]]+[0-9]+)?([[:space:]]|$)" \
        <<< "$wan_block" || return 1

    tunnel_block="$(
        awk -v interface_name="$TUNNEL_INTERFACE" '
            $0 ~ "^interface[[:space:]]+" interface_name "[[:space:]]*$" {
                inside = 1
                next
            }
            inside && /^interface[[:space:]]+/ {
                exit
            }
            inside && /^!/ {
                exit
            }
            inside {
                print
            }
        ' <<< "$config"
    )"
    ! contains "$tunnel_block" "set filter-map in $FIREWALL_MAP"
}

firewall_router_detail() {
    local config="$1"
    local -a missing=()

    contains "$config" "filter-map ipv4 $FIREWALL_MAP" ||
        missing+=("карта $FIREWALL_MAP")
    grep -Eqi 'match tcp any (any eq|eq) (80|http)([[:space:]]|$)' \
        <<< "$config" || missing+=("http")
    grep -Eqi 'match tcp any (any eq|eq) (443|https)([[:space:]]|$)' \
        <<< "$config" || missing+=("https")
    grep -Eqi 'match (tcp|udp) any (any eq|eq) (53|dns|domain)([[:space:]]|$)' \
        <<< "$config" || missing+=("dns")
    grep -Eqi 'match udp any (any eq|eq) (123|ntp)([[:space:]]|$)' \
        <<< "$config" || missing+=("ntp")
    contains "$config" "match icmp any any" || missing+=("icmp")

    if ! awk -v interface_name="$WAN_INTERFACE" -v map_name="$FIREWALL_MAP" '
        $0 ~ "^interface[[:space:]]+" interface_name "[[:space:]]*$" {
            inside = 1
            next
        }
        inside && (/^interface[[:space:]]+/ || /^!/) {
            exit
        }
        inside && $0 ~ "set filter-map in " map_name \
            "([[:space:]]+[0-9]+)?([[:space:]]|$)" {
            found = 1
        }
        END {
            exit(found ? 0 : 1)
        }
    ' <<< "$config"; then
        missing+=("назначение на $WAN_INTERFACE")
    fi

    if ((${#missing[@]} == 0)); then
        printf 'соответствует'
    else
        local IFS=', '
        printf 'нет: %s' "${missing[*]}"
    fi
}

check_4_firewall() {
    local title="Межсетевой экран EcoRouter"
    local hq_config="$1"
    local br_config="$2"
    local hq_ok=no
    local br_ok=no
    local hq_detail
    local br_detail

    firewall_router_ok "$hq_config" && hq_ok=yes
    firewall_router_ok "$br_config" && br_ok=yes
    hq_detail="$(firewall_router_detail "$hq_config")"
    br_detail="$(firewall_router_detail "$br_config")"

    if [[ "$hq_ok$br_ok" == yesyes ]]; then
        set_result 4 1 "$title" \
            "HQ-RTR и BR-RTR: WAN-фильтр разрешает http, https, dns, ntp и icmp; остальное блокируется политикой фильтра"
    elif [[ "$hq_ok" == yes || "$br_ok" == yes ]] ||
        { contains "$hq_config" "$FIREWALL_MAP" && contains "$br_config" "$FIREWALL_MAP"; }; then
        set_result 4 0.5 "$title" \
            "HQ-RTR: $hq_detail; BR-RTR: $br_detail"
    else
        set_result 4 0 "$title" \
            "HQ-RTR: $hq_detail; BR-RTR: $br_detail"
    fi
}

check_5_cups() {
    local title="CUPS PDF-принтер"
    local output
    local server_ok=no
    local client_ok=no
    local default_printer=""

    output="$(linux_remote "$HQ_SRV_IP" "
systemctl is-active --quiet cups && echo SERVICE:yes
lpstat -p '$CUPS_SERVER_QUEUE' >/dev/null 2>&1 && echo QUEUE:yes
lpstat -a '$CUPS_SERVER_QUEUE' >/dev/null 2>&1 && echo ACCEPTING:yes
ss -lnt 2>/dev/null | grep -q ':$CUPS_SERVER_PORT ' && echo LISTEN:yes
" 2>/dev/null)" || true

    contains "$output" "SERVICE:yes" &&
        contains "$output" "QUEUE:yes" &&
        contains "$output" "ACCEPTING:yes" &&
        contains "$output" "LISTEN:yes" && server_ok=yes

    default_printer="$(lpstat -d 2>/dev/null | awk -F: '{gsub(/^[ \t]+/, "", $2); print $2}')"
    if [[ "$default_printer" == "$CUPS_CLIENT_QUEUE" ]] &&
        lpstat -v "$CUPS_CLIENT_QUEUE" 2>/dev/null |
            grep -Fq "/printers/$CUPS_SERVER_QUEUE"; then
        client_ok=yes
    fi

    if [[ "$server_ok$client_ok" == yesyes ]]; then
        set_result 5 1 "$title" "PDF-принтер опубликован и установлен на HQ-CLI по умолчанию"
    elif [[ "$server_ok" == yes ]]; then
        set_result 5 0.5 "$title" \
            "Сервер работает; очередь HQ-CLI или принтер по умолчанию не подтверждены"
    else
        set_result 5 0 "$title" \
            "CUPS server=$server_ok, client=$client_ok, default=${default_printer:-не найден}"
    fi
}

check_6_rsyslog() {
    local title="Централизованный rsyslog"
    local output
    local br_output
    local found=0
    local expected
    local self_log=no
    local listener=no
    local br_client=no
    local router_clients=0
    local hq_config="$1"
    local br_config="$2"

    output="$(linux_remote "$HQ_SRV_IP" "
systemctl is-active rsyslog 2>/dev/null || true
ss -lntu 2>/dev/null | grep ':$LOG_SERVER_PORT ' || true
find '$LOG_ROOT' -mindepth 2 -maxdepth 2 -type f -name '$LOG_FILE_NAME' \
    -printf 'LOG:%h:%s\n' 2>/dev/null || true
" 2>/dev/null)" || true
    contains "$output" "active" &&
        grep -Eq ":$LOG_SERVER_PORT[[:space:]]" <<< "$output" && listener=yes

    for expected in $LOG_HOSTS; do
        grep -Eqi "^LOG:${LOG_ROOT}/$(printf '%s' "$expected" | sed 's/[][\\.^$*+?{}|()]/\\&/g'):[1-9][0-9]*$" \
            <<< "$output" && found=$((found + 1))
    done
    grep -Eqi "^LOG:${LOG_ROOT}/HQ-SRV:" <<< "$output" && self_log=yes

    br_output="$(linux_remote "$BR_SRV_IP" "
systemctl is-active rsyslog 2>/dev/null || true
cat /etc/rsyslog.d/30-au-team-forward-warning.conf 2>/dev/null || true
" 2>/dev/null)" || true
    contains "$br_output" "active" &&
        contains "$br_output" "*.warning" &&
        contains "$br_output" "$HQ_SRV_IP" &&
        contains "$br_output" "$LOG_SERVER_PORT" && br_client=yes

    contains "$hq_config" "rsyslog host $HQ_SRV_IP mode $LOG_PROTOCOL port $LOG_SERVER_PORT" &&
        router_clients=$((router_clients + 1))
    contains "$br_config" "rsyslog host $HQ_SRV_IP mode $LOG_PROTOCOL port $LOG_SERVER_PORT" &&
        router_clients=$((router_clients + 1))

    if ((found == 3 && router_clients == 2)) &&
        [[ "$listener$br_client$self_log" == yesyesno ]]; then
        set_result 6 1 "$title" "Логи HQ-RTR, BR-RTR и BR-SRV размещены в отдельных каталогах"
    elif ((found >= 1)) || [[ "$listener$br_client" == yesyes ]]; then
        set_result 6 0.5 "$title" "Центральный сбор работает частично; найдено источников: $found из 3"
    else
        set_result 6 0 "$title" "Централизованный сбор логов не подтверждён"
    fi
}

check_7_logrotate() {
    local title="Ротация удалённых логов"
    local output
    local exists=no
    local weekly=no
    local size=no
    local compress=no
    local path=no
    local scheduler=no

    output="$(linux_remote "$HQ_SRV_IP" "
cat /etc/logrotate.d/au-team-remote 2>/dev/null || true
cat /etc/cron.d/au-team-remote-logrotate 2>/dev/null || true
logrotate -d /etc/logrotate.d/au-team-remote 2>&1 || true
" 2>/dev/null)" || true

    [[ -n "$output" ]] && exists=yes
    grep -Eq '^[[:space:]]*weekly[[:space:]]*$' <<< "$output" && weekly=yes
    grep -Eqi "^[[:space:]]*(minsize|size)[[:space:]]+$ROTATE_SIZE[[:space:]]*$" \
        <<< "$output" && size=yes
    grep -Eq '^[[:space:]]*compress[[:space:]]*$' <<< "$output" && compress=yes
    contains "$output" "$LOG_ROOT/*/*.log" && path=yes
    contains "$output" "/usr/sbin/logrotate" && scheduler=yes

    if [[ "$weekly$size$compress$path$scheduler" == yesyesyesyesyes ]]; then
        set_result 7 1 "$title" "Еженедельная ротация, сжатие и порог $ROTATE_SIZE настроены"
    elif [[ "$exists" == yes ]] &&
        { [[ "$weekly" == yes ]] || [[ "$compress" == yes ]] || [[ "$size" == yes ]]; }; then
        set_result 7 0.5 "$title" "Ротация настроена, но параметры отличаются от задания"
    else
        set_result 7 0 "$title" "Политика ротации не обнаружена"
    fi
}

check_8_monitoring() {
    local title="Prometheus и Grafana"
    local output
    local grafana_code=000
    local containers=0
    local targets=0
    local panels=0
    local login=no
    local dns=no

    getent hosts "$MON_DOMAIN" >/dev/null 2>&1 && dns=yes
    grafana_code="$(curl -sS --connect-timeout 5 --max-time 15 \
        -o /dev/null -w '%{http_code}' \
        -u "$GRAFANA_ADMIN_USER:$GRAFANA_ADMIN_PASSWORD" \
        "http://$MON_DOMAIN:$GRAFANA_PORT/api/user" 2>/dev/null || true)"
    [[ "$grafana_code" == 200 ]] && login=yes

    output="$(linux_remote "$HQ_SRV_IP" "
for c in prometheus grafana node-exporter-hq; do
    [[ \$(docker inspect -f '{{.State.Running}}' \"\$c\" 2>/dev/null) == true ]] && echo CONTAINER:\"\$c\"
done
curl -sS 'http://127.0.0.1:$PROMETHEUS_PORT/api/v1/targets' 2>/dev/null || true
docker exec grafana sh -c 'grep -R -E \"CPU usage|Memory usage|Root filesystem usage\" /var/lib/grafana/dashboards 2>/dev/null' || true
" 2>/dev/null)" || true

    containers="$(count_matches "$output" '^CONTAINER:')"
    targets="$(count_matches "$output" '"health":"up"')"
    grep -Fq "CPU usage" <<< "$output" && panels=$((panels + 1))
    grep -Fq "Memory usage" <<< "$output" && panels=$((panels + 1))
    grep -Fq "Root filesystem usage" <<< "$output" && panels=$((panels + 1))

    if ((containers == 3 && targets >= 2 && panels == 3)) &&
        [[ "$login$dns" == yesyes ]]; then
        set_result 8 1 "$title" "HQ-SRV и BR-SRV доступны, CPU, RAM и диск отображаются"
    elif ((containers >= 2 && targets >= 1)) || [[ "$login" == yes ]]; then
        set_result 8 0.5 "$title" \
            "Контейнеры=$containers/3, targets=$targets/2, панели=$panels/3, DNS=$dns, вход=$login"
    else
        set_result 8 0 "$title" \
            "Контейнеры=$containers/3, targets=$targets/2, DNS=$dns, вход=$login"
    fi
}

check_9_inventory() {
    local title="Инвентаризация Ansible"
    local output
    local playbook=no
    local hq_report=no
    local cli_report=no

    output="$(linux_remote "$BR_SRV_IP" "
test -s '$ANSIBLE_DIR/$INVENTORY_PLAYBOOK' && echo PLAYBOOK:yes
for f in '$ANSIBLE_DIR/$INVENTORY_REPORT_DIR'/*.yml; do
    [[ -f \"\$f\" ]] || continue
    echo FILE:\$(basename \"\$f\")
    cat \"\$f\"
done
" 2>/dev/null)" || true

    contains "$output" "PLAYBOOK:yes" && playbook=yes
    grep -Eqi 'hostname:[[:space:]]*"?hq-srv"?|FILE:HQ-SRV\.yml' <<< "$output" &&
        contains "$output" "$HQ_SRV_IP" && hq_report=yes
    grep -Eqi 'hostname:[[:space:]]*"?hq-cli"?|FILE:HQ-CLI\.yml' <<< "$output" &&
        contains "$output" "$HQ_CLI_IP" && cli_report=yes

    if [[ "$playbook$hq_report$cli_report" == yesyesyes ]]; then
        set_result 9 1 "$title" "Созданы корректные YAML-отчёты HQ-SRV и HQ-CLI"
    elif [[ "$playbook" == yes ]] &&
        { [[ "$hq_report" == yes ]] || [[ "$cli_report" == yes ]]; }; then
        set_result 9 0.5 "$title" "Плейбук работает, но корректен только один отчёт"
    else
        set_result 9 0 "$title" "Механизм инвентаризации не обнаружен"
    fi
}

print_results() {
    local number
    local score
    local total
    local title
    local detail
    local title_line
    local detail_line
    local -a title_lines
    local -a detail_lines
    local line_count
    local line_index
    local table_file="$TMP_DIR/results.tsv"
    local python_bin=""

    wrap_text() {
        local text="$1"
        local width="$2"

        printf '%s\n' "$text" | fold -s -w "$width"
    }

    printf '\n%sРезультаты проверки module_3%s\n\n' "$C_BOLD" "$C_RESET"
    printf '№\tБалл\tКритерий\tРезультат\n' > "$table_file"

    for number in $(seq 1 13); do
        case "$number" in
            10)
                score=N/A
                title="Резервное копирование EcoRouter"
                detail="Отсутствует в текущем задании"
                ;;
            11)
                score=N/A
                title="Fail2ban для SSH"
                detail="Проверяется вручную"
                ;;
            12)
                score=N/A
                title="Кибер-бекап"
                detail="Проверяется вручную"
                ;;
            13)
                score=N/A
                title="Отчёт по ГОСТ"
                detail="Проверяется вручную"
                ;;
            *)
                score="${RESULT_SCORE[$number]:-0}"
                title="${RESULT_TITLE[$number]:-Не проверено}"
                detail="${RESULT_DETAIL[$number]:-Нет результата}"
                ;;
        esac

        mapfile -t title_lines < <(wrap_text "$title" 40)
        mapfile -t detail_lines < <(wrap_text "$detail" 85)
        line_count="${#title_lines[@]}"
        ((${#detail_lines[@]} > line_count)) &&
            line_count="${#detail_lines[@]}"

        for ((line_index = 0; line_index < line_count; line_index++)); do
            title_line="${title_lines[$line_index]:-}"
            detail_line="${detail_lines[$line_index]:-}"
            if ((line_index == 0)); then
                printf '%s\t%s\t%s\t%s\n' \
                    "$number" "$score" "$title_line" "$detail_line" \
                    >> "$table_file"
            else
                printf '\t\t%s\t%s\n' "$title_line" "$detail_line" \
                    >> "$table_file"
            fi
        done
    done

    if command -v python3 >/dev/null 2>&1; then
        python_bin=python3
    elif command -v python >/dev/null 2>&1; then
        python_bin=python
    fi

    if [[ -n "$python_bin" ]]; then
        TABLE_FILE="$table_file" \
            PYTHONUTF8=1 \
            PYTHONIOENCODING=utf-8 \
            TABLE_C_RESET="$C_RESET" \
            TABLE_C_RED="$C_RED" \
            TABLE_C_GREEN="$C_GREEN" \
            TABLE_C_YELLOW="$C_YELLOW" \
            "$python_bin" - <<'PY'
import csv
import os

with open(os.environ["TABLE_FILE"], encoding="utf-8", newline="") as source:
    rows = list(csv.reader(source, delimiter="\t"))

widths = [
    max(len(row[index]) for row in rows)
    for index in range(len(rows[0]))
]

colors = {
    "1": os.environ.get("TABLE_C_GREEN", ""),
    "0.5": os.environ.get("TABLE_C_YELLOW", ""),
    "0": os.environ.get("TABLE_C_RED", ""),
}
reset = os.environ.get("TABLE_C_RESET", "")

for row_index, row in enumerate(rows):
    cells = [
        value.ljust(widths[index])
        for index, value in enumerate(row)
    ]
    if row_index > 0 and row[1] in colors and colors[row[1]]:
        cells[1] = f"{colors[row[1]]}{cells[1]}{reset}"
    print(" | ".join(cells))
    if row_index == 0:
        print("-+-".join("-" * width for width in widths))
PY
    elif column --help 2>&1 | grep -q -- '--output-separator'; then
        column -t -s $'\t' -o ' | ' "$table_file"
    else
        column -t -s $'\t' "$table_file"
    fi

    total="$((TOTAL_HALF_POINTS / 2))"
    if ((TOTAL_HALF_POINTS % 2)); then
        total="${total}.5"
    fi
    printf '\n%sИтого: %s / 9 баллов%s\n' "$C_BOLD" "$total" "$C_RESET"
}

self_test() {
    local number
    for number in 1 2 3 4 5 6 7 8 9; do
        case $((number % 3)) in
            0) set_result "$number" 0 "Тестовый критерий $number" "Ошибка" ;;
            1) set_result "$number" 1 "Тестовый критерий $number" "Соответствует" ;;
            2) set_result "$number" 0.5 "Тестовый критерий $number" "Частично" ;;
        esac
    done
    print_results
}

main() {
    local hq_router_config=""
    local br_router_config=""
    local hq_sa=""
    local br_sa=""

    if [[ "${1:-}" == --self-test ]]; then
        self_test
        return
    fi

    [[ $EUID -eq 0 ]] ||
        warn "Запуск не от root ограничит установку диагностических пакетов"
    install_dependencies || warn "Некоторые проверки могут быть недоступны"
    create_router_expect

    log "1/9 Domain user import"
    check_1_users
    log "2/9 PKI and HTTPS"
    check_2_pki

    log "Reading EcoRouter configurations and IPsec state"
    hq_router_config="$(router_command "$HQ_RTR_SSH_HOST" "show running-config" || true)"
    br_router_config="$(router_command "$BR_RTR_SSH_HOST" "show running-config" || true)"
    hq_sa="$(router_command "$HQ_RTR_SSH_HOST" "show crypto-ipsec ike security-associations" || true)"
    br_sa="$(router_command "$BR_RTR_SSH_HOST" "show crypto-ipsec ike security-associations" || true)"

    log "3/9 Encrypted tunnel"
    check_3_ipsec "$hq_router_config" "$br_router_config" "$hq_sa" "$br_sa"
    log "4/9 Firewall"
    check_4_firewall "$hq_router_config" "$br_router_config"
    log "5/9 CUPS"
    check_5_cups
    log "6/9 Rsyslog"
    check_6_rsyslog "$hq_router_config" "$br_router_config"
    log "7/9 Log rotation"
    check_7_logrotate
    log "8/9 Monitoring"
    check_8_monitoring
    log "9/9 Ansible inventory"
    check_9_inventory

    print_results
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
