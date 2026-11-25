#!/usr/bin/env bash
set -euo pipefail
stage="$1"
port="$2"
[[ "$stage" =~ ^/tmp/proxy-tunnel-prototype\.[A-Za-z0-9]+$ ]]
[[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1024 && port <= 65535))
[[ $(id -u) == 0 && $(uname -m) == x86_64 ]]
systemd_version=$(systemctl --version | head -n1 | awk '{print $2}')
((systemd_version >= 247)) || { echo 'Нужен systemd 247+ (Ubuntu 22.04+ / Debian 11+).' >&2; exit 1; }
base=/opt/proxy-tunnel-prototype
conf=/etc/proxy-tunnel-prototype
unit=/etc/systemd/system/proxy-tunnel-prototype.service
service=proxy-tunnel-prototype
# Refuse a port owned by another service. Reuse is only allowed for our active unit.
if command -v ss >/dev/null && ss -H -lntu "sport = :$port" | grep -q .; then
  systemctl is-active --quiet "$service" || { echo 'Выбранный порт уже занят.' >&2; exit 1; }
  grep -q "\"listen_port\":$port[,}]" "$conf/config.json" || { echo 'Выбранный порт уже занят.' >&2; exit 1; }
fi
echo '699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968  '"$stage/engine.tar.gz" | sha256sum -c - >/dev/null
tar -xzf "$stage/engine.tar.gz" -C "$stage" --strip-components=1 sing-box-1.14.4-linux-amd64/sing-box
chmod 700 "$stage/sing-box"
"$stage/sing-box" check -c "$stage/config.json"
mkdir -p "$base" "$conf"
chmod 755 "$base"
chmod 700 "$conf"
had_bin=0; had_conf=0; had_unit=0; was_active=0; ufw_added=0
[[ ! -f "$base/sing-box" ]] || { cp -p "$base/sing-box" "$stage/old-bin"; had_bin=1; }
[[ ! -f "$conf/config.json" ]] || { cp -p "$conf/config.json" "$stage/old-conf"; had_conf=1; }
[[ ! -f "$unit" ]] || { cp -p "$unit" "$stage/old-unit"; had_unit=1; }
systemctl is-active --quiet "$service" && was_active=1 || true
rollback() {
  systemctl stop "$service" 2>/dev/null || true
  if ((had_bin)); then cp -p "$stage/old-bin" "$base/sing-box"; else rm -f "$base/sing-box"; fi
  if ((had_conf)); then cp -p "$stage/old-conf" "$conf/config.json"; else rm -f "$conf/config.json"; fi
  if ((had_unit)); then cp -p "$stage/old-unit" "$unit"; else systemctl disable "$service" 2>/dev/null || true; rm -f "$unit"; fi
  systemctl daemon-reload
  if ((was_active)); then systemctl start "$service" || true; fi
  if ((ufw_added)); then ufw --force delete allow "$port" comment 'ProxyTunnelPrototype' >/dev/null || true; fi
  echo 'Подготовка не завершена. Прежняя конфигурация восстановлена.' >&2
}
trap rollback ERR
systemctl stop "$service" 2>/dev/null || true
install -m 755 "$stage/sing-box" "$base/sing-box"
install -m 600 "$stage/config.json" "$conf/config.json"
cat >"$unit" <<'UNIT'
[Unit]
Description=Proxy Tunnel Prototype encrypted transport
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=true
LoadCredential=tunnel.json:/etc/proxy-tunnel-prototype/config.json
ExecStart=/opt/proxy-tunnel-prototype/sing-box run -c %d/tunnel.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  if ! ufw status | grep -q "$port.*ProxyTunnelPrototype"; then
    ufw allow "$port" comment 'ProxyTunnelPrototype' >/dev/null
    ufw_added=1
  fi
fi
systemctl daemon-reload
systemctl enable --now "$service" >/dev/null
sleep 2
systemctl is-active --quiet "$service"
trap - ERR
echo PT-READY
