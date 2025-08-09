#!/bin/bash
# Firewall для IPv4 + VPN (VPN клиенты — только в интернет).
# Полностью отключает/блокирует IPv6.
set -euo pipefail

### ========== ПЕРЕМЕННЫЕ ==========
WAN_IF="eno1"               # интерфейс, на котором приходит Интернет (WAN)
LAN_IF="eno3"               # интерфейс в локальную сеть (LAN)
LAN_NET="192.168.1.0/24"    # сеть локалки
LOOPBACK="127.0.0.1"

# Порты Minecraft
MINE_PORT_RANGE="25560:25600"      

# DNS/NTP сервера, к которым разрешаем исходящие запросы (мы — клиент)
DNS_SERVERS=(1.1.1.1 8.8.8.8 8.8.4.4)
NTP_SERVERS=("216.239.35.0/28" "162.159.200.1" "129.6.15.28" "129.6.15.29")

# VPN (Amnezia) 
VPN_IF="amn0"
VPN_NET="172.29.172.0/24"

# Публичный IP — используется, чтобы запретить доступ VPN к самому роутеру
PUBLIC_IP="93.100.111.248"

### ========== ФУНКЦИЯ: Применяем sysctl для защиты ==========
apply_sysctl() {
  echo "Применение sysctl настроек..."

  # Общие (IPv4 routing + базовая защита)
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv4.tcp_syncookies=1
  sysctl -w net.ipv4.tcp_max_syn_backlog=4096
  sysctl -w net.core.somaxconn=4096

  # rp_filter (простая защита от spoof)
  sysctl -w net.ipv4.conf.$WAN_IF.rp_filter=1
  sysctl -w net.ipv4.conf.all.rp_filter=1

  # ===== Тюнинг conntrack =====
  # Увеличиваем максимум conntrack .
  sysctl -w net.netfilter.nf_conntrack_max=262144
  # Удлиним время для established соединений (уменьшает churn в таблице)
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=120

  # ===== Полный запрет IPv6 =====
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sysctl -w net.ipv6.conf.default.disable_ipv6=1
  sysctl -w net.ipv6.conf.lo.disable_ipv6=1

  echo "sysctl applied"
}

### ========== СБРОС ПРАВИЛ ==========
echo "Сбрасываем старые правила..."
iptables -F
iptables -X 2>/dev/null || true
iptables -t nat -F
iptables -t mangle -F

# Очистим старые ip6tables и поставим политику DROP (полностью блокируем IPv6)
ip6tables -F 2>/dev/null || true
ip6tables -X 2>/dev/null || true
ip6tables -t mangle -F 2>/dev/null || true
ip6tables -P INPUT DROP 2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true

### ========== ЛОГИРОВАНИЕ С ЛИМИТОМ ==========
iptables -N LOG_DROP 2>/dev/null || true
iptables -F LOG_DROP || true
iptables -A LOG_DROP -m limit --limit 2/min --limit-burst 5 -j LOG --log-prefix "FW-DROP: " --log-level 4
iptables -A LOG_DROP -j DROP

### ========== IPv4: политика по умолчанию ==========
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Сразу блокируем некорректные (INVALID) пакеты
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Ранние фильтры — экономят ресурсы conntrack и отсекают мусор
# 1) Фрагменты — часто используются в атаках, и они требуют conntrack; лучше дропать/логировать
iptables -A INPUT -f -j LOG_DROP

# 2) "Странные" TCP-флаги (NULL, XMAS, SYN+FIN и т.д.)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROP   # NULL
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROP    # XMAS
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG_DROP

# Anti-bogon — не даём приватные/резервные адреса приходить на WAN
iptables -A INPUT -i "$WAN_IF" -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i "$WAN_IF" -s 100.64.0.0/10 -j DROP
iptables -A INPUT -i "$WAN_IF" -s 169.254.0.0/16 -j DROP
iptables -A INPUT -i "$WAN_IF" -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i "$WAN_IF" -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i "$WAN_IF" -s 224.0.0.0/3 -j DROP

# Разрешаем локалхост
iptables -A INPUT -i lo -j ACCEPT

# Разрешаем ESTABLISHED/RELATED
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### ========== NAT и форвардинг (мы — роутер) ==========
# Маскарадинг трафика LAN -> Internet (на WAN_IF)
iptables -t nat -A POSTROUTING -o "$WAN_IF" -s "$LAN_NET" -j MASQUERADE

# Разрешаем маршрутизацию LAN->WAN и ответные пакеты
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -s "$LAN_NET" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -d "$LAN_NET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### ========== СЕРВИСЫ (IPv4) — строго и с лимитами ==========

# ---------- SSH (22) ----------
# Ограничение: не больше 5 NEW / мин (recent), SYN-pps ограничение 20/s (hashlimit)
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 6 --name SSH -j LOG_DROP
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 22 --syn -m hashlimit --hashlimit 20/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name ssh_syn -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 22 -j LOG_DROP
# Разрешаем SSH из локалки без этих WAN-ограничений (локалка считается доверенной)
iptables -A INPUT -i "$LAN_IF" -p tcp --dport 22 -j ACCEPT

# ---------- HTTP/HTTPS (80,443) ----------
iptables -A INPUT -i "$WAN_IF" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --set --name WEB
iptables -A INPUT -i "$WAN_IF" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 30 --name WEB -j LOG_DROP
iptables -A INPUT -i "$WAN_IF" -p tcp -m multiport --dports 80,443 --syn -m hashlimit --hashlimit 80/sec --hashlimit-burst 160 --hashlimit-mode srcip --hashlimit-name web_syn -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 200 --connlimit-mask 32 -j REJECT
iptables -A INPUT -i "$WAN_IF" -p tcp -m multiport --dports 80,443 -j ACCEPT

# ---------- Minecraft (TCP + UDP) ----------

# TCP
iptables -A INPUT -i "$WAN_IF" -p tcp --dport $MINE_PORT_RANGE \
  -m conntrack --ctstate NEW -m recent --set --name MINE
iptables -A INPUT -i "$WAN_IF" -p tcp --dport $MINE_PORT_RANGE \
  -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 10 --name MINE -j LOG_DROP
iptables -A INPUT -i "$WAN_IF" -p tcp --dport $MINE_PORT_RANGE \
  --syn -m hashlimit --hashlimit 50/sec --hashlimit-burst 100 --hashlimit-mode srcip \
  --hashlimit-name mine_tcp_syn -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport $MINE_PORT_RANGE -j LOG_DROP

# UDP
iptables -A INPUT -i "$WAN_IF" -p udp --dport $MINE_PORT_RANGE \
  -m conntrack --ctstate NEW -m recent --set --name MINE_UDP
iptables -A INPUT -i "$WAN_IF" -p udp --dport $MINE_PORT_RANGE \
  -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 20 --name MINE_UDP -j LOG_DROP
iptables -A INPUT -i "$WAN_IF" -p udp --dport $MINE_PORT_RANGE \
  -m hashlimit --hashlimit 50/sec --hashlimit-burst 100 --hashlimit-mode srcip \
  --hashlimit-name mine_udp -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport $MINE_PORT_RANGE -j LOG_DROP


# ---------- VPN (UDP 33186) ----------
# Ограничение pps — примерно 200 pps / src
iptables -A INPUT -i "$WAN_IF" -p udp --dport 33186 -m hashlimit --hashlimit 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-name vpn_udp -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 33186 -j LOG_DROP
# Разрешаем также из локалки 
iptables -A INPUT -i "$LAN_IF" -p udp --dport 33186 -j ACCEPT

# ---------- VNC (5900) ----------
# VNC открыт, с лимитами 30 pps / src
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 5900 -m conntrack --ctstate NEW -m recent --set --name VNC
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 5900 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 11 --name VNC -j LOG_DROP
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 5900 --syn -m hashlimit --hashlimit 30/sec --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name vnc_syn -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 5900 -m connlimit --connlimit-above 5 --connlimit-mask 32 -j REJECT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 5900 -j ACCEPT

# ---------- Nginx на 27231 ----------
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 27231 -m conntrack --ctstate NEW -m recent --set --name NGINX27231
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 27231 -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 30 --name NGINX27231 -j LOG_DROP
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 27231 --syn -m hashlimit --hashlimit 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name nginx27231_syn -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 27231 -j ACCEPT

# ---------- ss-server (Shadowsocks) 8388 — локальный ----------
iptables -A INPUT -p tcp --dport 8388 -s "$LAN_NET" -j ACCEPT
iptables -A INPUT -p udp --dport 8388 -s "$LAN_NET" -j ACCEPT
iptables -A INPUT -p tcp --dport 8388 -s "$LOOPBACK" -j ACCEPT
iptables -A INPUT -p udp --dport 8388 -s "$LOOPBACK" -j ACCEPT
iptables -A INPUT -p tcp --dport 8388 -i "$WAN_IF" -j LOG_DROP
iptables -A INPUT -p udp --dport 8388 -i "$WAN_IF" -j LOG_DROP

# ---------- DNS и NTP (только как клиент) ----------
for s in "${DNS_SERVERS[@]}"; do
  iptables -A OUTPUT -o "$WAN_IF" -p udp --dport 53 -d "$s" -j ACCEPT
  iptables -A OUTPUT -o "$WAN_IF" -p tcp --dport 53 -d "$s" -j ACCEPT
done
iptables -A INPUT -p udp --dport 53 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j LOG_DROP
iptables -A INPUT -p tcp --dport 53 -j LOG_DROP

for s in "${NTP_SERVERS[@]}"; do
  iptables -A OUTPUT -o "$WAN_IF" -p udp --dport 123 -d "$s" -j ACCEPT
done
iptables -A INPUT -p udp --dport 123 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp --dport 123 -j LOG_DROP

# ---------- LAN-only сервисы (разрешаем только из LAN) ----------

iptables -A INPUT -p udp --dport 1900 -s "$LAN_NET" -j ACCEPT    # SSDP
iptables -A INPUT -p udp --dport 1900 -j LOG_DROP

iptables -A INPUT -p udp --dport 5353 -s "$LAN_NET" -j ACCEPT    # mDNS
iptables -A INPUT -p udp --dport 5353 -j LOG_DROP

# DHCP: сервер сам выступает DHCP сервером
# Здесь разрешаем DHCP запросы/ответы от LAN.
# Запросы клиентов (68 -> 67)
iptables -A INPUT -i "$LAN_IF" -p udp --sport 68 --dport 67 -j ACCEPT
# Ответы сервера (67 -> 68)
iptables -A OUTPUT -o "$LAN_IF" -p udp --sport 67 --dport 68 -j ACCEPT

iptables -A INPUT -p tcp --dport 3306 -s "$LAN_NET" -j ACCEPT    # MySQL локально
iptables -A INPUT -p tcp --dport 3306 -s "$LOOPBACK" -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j LOG_DROP

iptables -A INPUT -p tcp --dport 27017 -s "$LAN_NET" -j ACCEPT  # MongoDB локально
iptables -A INPUT -p tcp --dport 27017 -s "$LOOPBACK" -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -j LOG_DROP

# memcached — запрещаем на WAN
iptables -A INPUT -p tcp --dport 11211 -i "$WAN_IF" -j DROP
iptables -A INPUT -p udp --dport 11211 -i "$WAN_IF" -j DROP

# ---------- ICMP ----------
# ICMP из LAN — разрешаем
iptables -A INPUT -p icmp -s "$LAN_NET" -m limit --limit 70/sec --limit-burst 140 -j ACCEPT
# ICMP из WAN — ограничиваем и дропаем частые попытки
iptables -A INPUT -p icmp -i "$WAN_IF" -m limit --limit 3/sec --limit-burst 6 -j LOG_DROP

### ========== VPN: NAT и изоляция VPN клиентов ==========
# NAT для VPN клиентов — их трафик в интернет будет MASQUERADE'иться на WAN
iptables -t nat -A POSTROUTING -s "$VPN_NET" -o "$WAN_IF" -j MASQUERADE

# Разрешаем VPN -> WAN (интернет)
iptables -A FORWARD -i "$VPN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$VPN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Блокируем доступ VPN клиентов к локальным подсетям и самому роутеру:
iptables -A FORWARD -i "$VPN_IF" -d 10.0.0.0/8 -j DROP
#iptables -A FORWARD -i "$VPN_IF" -d 172.16.0.0/12 -j DROP            # оставим
iptables -A FORWARD -i "$VPN_IF" -d 192.168.0.0/16 -j DROP
#iptables -A FORWARD -i "$VPN_IF" -d 172.17.0.0/16 -j DROP            # docker default оставим
iptables -A FORWARD -i "$VPN_IF" -d 192.168.122.0/24 -j DROP       # libvirt default
iptables -A FORWARD -i "$VPN_IF" -d 127.0.0.0/8 -j DROP

# Блокируем доступ VPN к самому серверу (публичный IP и VPN интерфейс IP)
if [[ -n "$PUBLIC_IP" ]]; then
  iptables -A FORWARD -i "$VPN_IF" -d "$PUBLIC_IP" -j DROP
fi
iptables -A FORWARD -i "$VPN_IF" -d "${VPN_NET%%.*}.1" -j DROP || true  # пример блокировки .1 (если не резолвится, не критично)

### ========== Финальная настройка и запуска sysctl ==========
# Разрешаем исходящие DHCP-клиенту (sport 68)
iptables -A OUTPUT -p udp --sport 68 -j ACCEPT || true

apply_sysctl

echo "Правила применены."
echo "iptables -L -n -v --line-numbers"
echo "ip6tables -L -n -v --line-numbers (должен показывать DROP/пусто, т.к. IPv6 отключён)"
