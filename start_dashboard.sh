#!/usr/bin/env bash
# =================================================================
# NICS CyberLab – Professional Starter
# Gunicorn + tcpdump (capabilities) + libpcap + Port Management
# =================================================================
# Design principles:
# - Python and Gunicorn run UNPRIVILEGED
# - Network capture delegated ONLY to tcpdump with minimal capabilities
# - Safe & idempotent startup
# - No hard failures if optional components are missing
# =================================================================

set -euo pipefail

# -----------------------------
# CONFIG
# -----------------------------
PORT=5001
TIMEOUT=20000

APP_PATH="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
SCENARIO_CAPTURE_PID=""

# --- Python venv resolution ---
# Override con variable de entorno: export NICS_VENV_PYTHON=/ruta/a/python
# Si no se define, se busca el intérprete en orden de preferencia dentro del venv.
#
# Candidatos de raíz del venv, en orden (primero que exista gana):
#   1. $NICS_VENV_ROOT  (variable de entorno externa)
#   2. $HOME/Desktop/Openstack/myenv  (ubicación original, portable vía $HOME)
#   3. $APP_PATH/.venv  (venv local al repositorio)
#   4. $APP_PATH/venv
_resolve_venv_python() {
    # Si ya viene un binario explícito, lo validamos y usamos directamente.
    if [ -n "${NICS_VENV_PYTHON:-}" ]; then
        if [ -x "$NICS_VENV_PYTHON" ]; then
            echo "$NICS_VENV_PYTHON"
            return 0
        fi
        echo "[WARN] NICS_VENV_PYTHON=$NICS_VENV_PYTHON no es ejecutable — buscando candidatos automáticos..." >&2
    fi

    local candidates=(
        "${NICS_VENV_ROOT:-}"
        "$HOME/Desktop/Openstack/myenv"
        "$APP_PATH/.venv"
        "$APP_PATH/venv"
        "$APP_PATH/myenv"
    )
    local versions=(python3.12 python3.11 python3.10 python3.9 python3)

    for root in "${candidates[@]}"; do
        [ -z "$root" ] && continue
        for ver in "${versions[@]}"; do
            local candidate="$root/bin/$ver"
            if [ -x "$candidate" ]; then
                echo "$candidate"
                return 0
            fi
        done
    done
    return 1
}

if ! VENV_PYTHON="$(_resolve_venv_python)"; then
    # No se encontró ningún venv. Saldremos en la sección [1/6] con mensaje claro.
    VENV_PYTHON=""
fi

# -----------------------------
# UTILS
# -----------------------------
section () {
    echo
    echo "============================================="
    echo " $1"
    echo "============================================="
}

ok ()   { echo " [OK]   $1"; }
warn () { echo " [WARN] $1"; }
info () { echo " [INFO] $1"; }
err ()  { echo " [ERR]  $1"; }

CLEANUP_DONE=0
cleanup() {
    # Bug real encontrado 2026-10-15: `trap cleanup EXIT INT TERM` ejecutaba
    # cleanup() DOS VECES por cada Ctrl+C -- una vez de inmediato vía el trap
    # INT, y OTRA VEZ vía el trap EXIT en cuanto gunicorn (que recibe su
    # propio SIGINT directo del terminal, al estar en el mismo grupo de
    # procesos en primer plano) terminaba su propio apagado y el script
    # llegaba a su `exit "$GUNICORN_RC"` final. La segunda pasada volvía a
    # pedir la contraseña de sudo justo cuando la terminal ya estaba en un
    # estado confuso por la primera, dejando el `read` de sudo bloqueado
    # para siempre -- la terminal "se quedaba parada" sin aceptar ninguna
    # entrada más, ni siquiera otro Ctrl+C. Idempotente ahora: como mucho se
    # ejecuta una vez real, sea cual sea la combinación de traps que la
    # dispare. Además se desarma el propio trap INT/TERM nada más entrar,
    # para que un segundo Ctrl+C impaciente mientras cleanup() ya está
    # pidiendo la contraseña no reentre a mitad de la limpieza.
    trap '' INT TERM
    if [ "$CLEANUP_DONE" = "1" ]; then
        return
    fi
    CLEANUP_DONE=1
    echo
    info "Ejecutando limpieza final..."

    # Deliberadamente NO depende de "$SCENARIO_CAPTURE_PID" (bug real
    # encontrado 2026-10-13, segunda vuelta): nics_scenario_captures.sh tiene
    # su propio candado por mkdir (acquire_lock) y, si otra instancia ya
    # estaba corriendo (p.ej. una de hace semanas que nunca se llegó a matar),
    # la instancia que ACABA de lanzar esta ejecución de start_dashboard.sh
    # detecta el candado, imprime "Refusing to start" y sale casi al
    # instante -- dejando "$SCENARIO_CAPTURE_PID" apuntando a un proceso que
    # ya llevaba muerto desde el principio. El "if ps -p ... ; then" de
    # antes comprobaba justo ESE PID y, al estar ya muerto, se saltaba TODO
    # el bloque de limpieza sin ni intentarlo -- el huérfano real (otro PID
    # distinto) seguía vivo sin que nadie lo tocara. Ahora se busca por
    # patrón (pgrep -f), no por ese PID concreto, así que encuentra y para
    # el huérfano real sea cual sea su PID.
    if pgrep -f nics_scenario_captures.sh > /dev/null 2>&1 || pgrep -f "tcpdump -i tap" > /dev/null 2>&1; then
        info "Deteniendo nics_scenario_captures.sh y sus capturas tcpdump en curso..."

        # Sin -n a propósito (bug real encontrado 2026-10-13, primera
        # vuelta): con -n ("non-interactive"), si el ticket de sudo de esta
        # terminal ya había caducado (este script puede llevar corriendo
        # semanas, muy por encima de los ~15 min que dura un ticket de
        # sudo), el kill fallaba en SILENCIO -- el "|| true" se tragaba el
        # error -- y dejaba todo huérfano corriendo indefinidamente, sin
        # ningún aviso real de que la limpieza no había funcionado. Ahora,
        # si hace falta, pregunta la contraseña aquí mismo, en esta misma
        # terminal; si no se proporciona, el resultado es el mismo de
        # siempre -- se quedan corriendo -- pero ya nunca de forma
        # silenciosa/engañosa.
        sudo -p "[sudo] contraseña para detener la captura de red (nics_scenario_captures.sh): " \
            bash -c 'pkill -TERM -f nics_scenario_captures.sh; pkill -TERM -f "tcpdump -i tap"' 2>/dev/null || true

        for _ in {1..10}; do
            if ! pgrep -f nics_scenario_captures.sh > /dev/null 2>&1 && ! pgrep -f "tcpdump -i tap" > /dev/null 2>&1; then
                break
            fi
            sleep 1
        done

        if pgrep -f nics_scenario_captures.sh > /dev/null 2>&1 || pgrep -f "tcpdump -i tap" > /dev/null 2>&1; then
            warn "El proceso sigue vivo. Forzando parada (reutiliza el ticket de sudo recién dado, no vuelve a pedir contraseña)..."
            sudo -n bash -c 'pkill -KILL -f nics_scenario_captures.sh; pkill -KILL -f "tcpdump -i tap"' 2>/dev/null || true
            sleep 1
        fi

        if ! pgrep -f nics_scenario_captures.sh > /dev/null 2>&1 && ! pgrep -f "tcpdump -i tap" > /dev/null 2>&1; then
            ok "nics_scenario_captures.sh y sus capturas tcpdump detenidos correctamente."
        else
            warn "No se pudo detener completamente nics_scenario_captures.sh (sigue corriendo -- probablemente no se dio la contraseña)."
        fi
    fi
}

trap cleanup EXIT INT TERM

# -----------------------------
# [1/6] PREPARATION
# -----------------------------
section "[1/6] Preparando entorno y scripts auxiliares"

if [ -f "$APP_PATH/free_port.sh" ]; then
    chmod +x "$APP_PATH/free_port.sh"
    ok "Script de limpieza de puertos listo."
else
    err "No se encuentra $APP_PATH/free_port.sh"
    exit 1
fi

if [ -z "$VENV_PYTHON" ] || [ ! -x "$VENV_PYTHON" ]; then
    err "No se encontró Python en ningún venv conocido."
    err "Candidatos probados:"
    err "  \$HOME/Desktop/Openstack/myenv  ->  $HOME/Desktop/Openstack/myenv"
    err "  \$APP_PATH/.venv               ->  $APP_PATH/.venv"
    err "  \$APP_PATH/venv                ->  $APP_PATH/venv"
    err ""
    err "Opciones para resolverlo:"
    err "  a) export NICS_VENV_PYTHON=/ruta/exacta/al/bin/python3.x"
    err "  b) export NICS_VENV_ROOT=/ruta/al/directorio/venv"
    err "  c) Crea un venv en $APP_PATH/.venv con: python3 -m venv $APP_PATH/.venv"
    exit 1
else
    VENV_VERSION="$("$VENV_PYTHON" --version 2>&1 || echo 'desconocida')"
    ok "VENV Python detectado: $VENV_PYTHON  ($VENV_VERSION)"
fi

# -----------------------------
# [2.5/6] SSH PERMISSIONS
# -----------------------------
section "[2.5/6] Ajustando permisos SSH..."

chmod 700 "$HOME/.ssh" 2>/dev/null || true
chmod 600 "$HOME/.ssh/my_key" 2>/dev/null || true
chmod 644 "$HOME/.ssh/my_key.pub" 2>/dev/null || true

# -----------------------------
# [2/6] SYSTEM DEPENDENCIES
# -----------------------------
section "[2/6] Verificando dependencias del sistema"

if ! dpkg -s libpcap-dev >/dev/null 2>&1; then
    warn "libpcap-dev no detectado."
    info "Instalando libpcap-dev (requiere sudo)..."
    sudo apt-get update && sudo apt-get install -y libpcap-dev
    ok "libpcap-dev instalado."
else
    ok "libpcap-dev ya está instalado."
fi

if ! command -v getcap >/dev/null 2>&1; then
    warn "getcap no disponible (paquete libcap2-bin)."
    info "Instálalo si quieres ver capacidades: sudo apt install libcap2-bin"
else
    ok "getcap disponible."
fi

# -----------------------------
# [2.8/6] DFIR DISK ACQUISITION – PRIVILEGIOS PERMANENTES
# -----------------------------
section "[2.8/6] Privilegios para adquisición de disco forense (DFIR)"

DISK_ACQ_SCRIPT="$APP_PATH/app_core/infrastructure/forensics/scripts/acquire_disk_kolla_libvirt.sh"
DISK_SUDOERS_DEST="/etc/sudoers.d/nicscyberlab-acquire-disk"
DISK_SUDOERS_USER="$(whoami)"

if [ ! -f "$DISK_ACQ_SCRIPT" ]; then
    warn "Script de disco forense no encontrado: $DISK_ACQ_SCRIPT"
    warn "La adquisición de disco DFIR no estará disponible."
elif sudo -n /bin/bash "$DISK_ACQ_SCRIPT" __nics_probe__ >/dev/null 2>&1; then
    ok "Regla NOPASSWD para adquisición de disco ya activa — no se pedirá contraseña."
else
    info "La adquisición de disco requiere contraseña actualmente (o el timestamp ha expirado)."
    info "Instalando regla sudoers permanente para $DISK_SUDOERS_USER ..."
    info "Se pedirá la contraseña UNA SOLA VEZ. Las próximas ejecuciones no la requerirán."

    # Escribir regla en fichero temporal con expansión de variables
    _DISK_TMP="$(mktemp /tmp/.nicscyberlab-disk-sudoers.XXXXXX)"
    cat > "$_DISK_TMP" << SUDOERS_BLOCK
# nicscyberlab_v3 -- DFIR disk acquisition
# Auto-generado por start_dashboard.sh -- NO editar manualmente
# Permite al usuario del servidor web adquirir disco sin contraseña
# para flujos Level B / DFIR automatizados. Solo aplica a ese script.
Defaults!NICS_DFIR_DISK_HELPER !requiretty
Cmnd_Alias NICS_DFIR_DISK_HELPER = /bin/bash ${DISK_ACQ_SCRIPT} *

${DISK_SUDOERS_USER} ALL=(root) NOPASSWD: NICS_DFIR_DISK_HELPER
SUDOERS_BLOCK

    set +e
    sudo install -m 440 -o root -g root "$_DISK_TMP" "$DISK_SUDOERS_DEST"
    _INSTALL_RC=$?
    set -e
    rm -f "$_DISK_TMP"

    if [ "$_INSTALL_RC" -eq 0 ]; then
        ok "Regla instalada en $DISK_SUDOERS_DEST"
        # Verificación final: el script ya debe funcionar sin contraseña
        if sudo -n /bin/bash "$DISK_ACQ_SCRIPT" __nics_probe__ >/dev/null 2>&1; then
            ok "Verificación OK — adquisición de disco funcionará sin contraseña en todas las ejecuciones futuras."
        else
            warn "Regla instalada pero la verificación aún falla. Intenta relanzar start_dashboard.sh."
        fi
    else
        warn "Instalación de regla sudoers cancelada o fallida (contraseña incorrecta o permisos)."
        warn "La adquisición de disco pedirá contraseña cada ~15 min (sudo timestamp)."
        warn "Para instalarlo manualmente ejecuta:"
        warn "  sudo install -m 440 -o root -g root <(cat <<EOF"
        warn "  Defaults!NICS_DFIR_DISK_HELPER !requiretty"
        warn "  Cmnd_Alias NICS_DFIR_DISK_HELPER = /bin/bash ${DISK_ACQ_SCRIPT} *"
        warn "  ${DISK_SUDOERS_USER} ALL=(root) NOPASSWD: NICS_DFIR_DISK_HELPER"
        warn "  EOF) $DISK_SUDOERS_DEST"
    fi
fi

# -----------------------------
# [2.9/6] NODE HEALTH – LIBERAR MEMORIA DEL HOST – PRIVILEGIOS PERMANENTES
# -----------------------------
section "[2.9/6] Privilegios para liberar memoria del host (Node Health)"

FREE_MEM_SCRIPT="$APP_PATH/app_core/infrastructure/node_health/scripts/free_host_memory.sh"
FREE_MEM_SUDOERS_DEST="/etc/sudoers.d/nicscyberlab-free-host-memory"
FREE_MEM_SUDOERS_USER="$(whoami)"

if [ ! -f "$FREE_MEM_SCRIPT" ]; then
    warn "Script de liberación de memoria no encontrado: $FREE_MEM_SCRIPT"
    warn "El botón 'Free Host Memory' de Node Health no podrá liberar cache de kernel (drop_caches)."
elif sudo -n /bin/bash "$FREE_MEM_SCRIPT" __nics_probe__ >/dev/null 2>&1; then
    ok "Regla NOPASSWD para liberar memoria del host ya activa — no se pedirá contraseña."
else
    info "Liberar memoria del host (drop_caches) requiere contraseña actualmente (o el timestamp ha expirado)."
    info "Instalando regla sudoers permanente para $FREE_MEM_SUDOERS_USER ..."
    info "Se pedirá la contraseña UNA SOLA VEZ. Las próximas ejecuciones no la requerirán."

    _FREE_MEM_TMP="$(mktemp /tmp/.nicscyberlab-free-mem-sudoers.XXXXXX)"
    cat > "$_FREE_MEM_TMP" << SUDOERS_BLOCK
# nicscyberlab_v3 -- Node Health: free host memory (drop_caches)
# Auto-generado por start_dashboard.sh -- NO editar manualmente
# Permite al usuario del servidor web liberar page cache/dentries/inodes
# del host (nunca swap, nunca borra datos) desde el botón de Node Health.
Defaults!NICS_FREE_HOST_MEMORY !requiretty
Cmnd_Alias NICS_FREE_HOST_MEMORY = /bin/bash ${FREE_MEM_SCRIPT} *

${FREE_MEM_SUDOERS_USER} ALL=(root) NOPASSWD: NICS_FREE_HOST_MEMORY
SUDOERS_BLOCK

    set +e
    sudo install -m 440 -o root -g root "$_FREE_MEM_TMP" "$FREE_MEM_SUDOERS_DEST"
    _INSTALL_RC=$?
    set -e
    rm -f "$_FREE_MEM_TMP"

    if [ "$_INSTALL_RC" -eq 0 ]; then
        ok "Regla instalada en $FREE_MEM_SUDOERS_DEST"
        if sudo -n /bin/bash "$FREE_MEM_SCRIPT" __nics_probe__ >/dev/null 2>&1; then
            ok "Verificación OK — el botón 'Free Host Memory' funcionará sin contraseña."
        else
            warn "Regla instalada pero la verificación aún falla. Intenta relanzar start_dashboard.sh."
        fi
    else
        warn "Instalación de regla sudoers cancelada o fallida (contraseña incorrecta o permisos)."
        warn "El botón 'Free Host Memory' solo hará gc.collect() en memoria de Python hasta que instales la regla."
        warn "Para instalarlo manualmente ejecuta:"
        warn "  sudo install -m 440 -o root -g root <(cat <<EOF"
        warn "  Defaults!NICS_FREE_HOST_MEMORY !requiretty"
        warn "  Cmnd_Alias NICS_FREE_HOST_MEMORY = /bin/bash ${FREE_MEM_SCRIPT} *"
        warn "  ${FREE_MEM_SUDOERS_USER} ALL=(root) NOPASSWD: NICS_FREE_HOST_MEMORY"
        warn "  EOF) $FREE_MEM_SUDOERS_DEST"
    fi
fi

# -----------------------------
# [3/6] TCPDUMP CAPABILITIES
# -----------------------------
section "[3/6] Configurando capacidades de red (tcpdump)"

TCPDUMP_BIN="$(command -v tcpdump || true)"

if [ -z "$TCPDUMP_BIN" ]; then
    warn "tcpdump no está instalado. La captura de red estará deshabilitada."
else
    ok "tcpdump detectado en: $TCPDUMP_BIN"

    TCPDUMP_CAPS="$(getcap "$TCPDUMP_BIN" 2>/dev/null || true)"

    if echo "$TCPDUMP_CAPS" | grep -q "cap_net_admin,cap_net_raw=eip"; then
        ok "tcpdump ya tiene capacidades de red."
    else
        info "tcpdump sin capacidades. Intentando aplicar (requiere sudo)..."

        if sudo -n true 2>/dev/null; then
            sudo setcap cap_net_raw,cap_net_admin=eip "$TCPDUMP_BIN" || true

            if getcap "$TCPDUMP_BIN" | grep -q "cap_net_admin,cap_net_raw=eip"; then
                ok "Capacidades aplicadas correctamente a tcpdump."
            else
                warn "No se pudieron aplicar capacidades a tcpdump."
                warn "La captura de red fallará si no se ejecuta como root."
            fi
        else
            warn "No hay sudo sin contraseña."
            warn "Ejecuta manualmente:"
            warn "sudo setcap cap_net_raw,cap_net_admin=eip $TCPDUMP_BIN"
        fi
    fi
fi

# -----------------------------
# [3.5/6] PYTHON CAPABILITIES
# -----------------------------
section "[3.5/6] Configurando capacidades de red (python)"

REAL_PY="$(readlink -f "$VENV_PYTHON" 2>/dev/null || true)"

if [ -z "$REAL_PY" ] || [ ! -f "$REAL_PY" ]; then
    warn "No se pudo resolver el python real desde el venv: $VENV_PYTHON"
    warn "Saltando setcap para python."
else
    ok "Python real detectado: $REAL_PY"

    PY_CAPS="$(getcap "$REAL_PY" 2>/dev/null || true)"

    if echo "$PY_CAPS" | grep -q "cap_net_admin,cap_net_raw=eip"; then
        ok "Python ya tiene capacidades de captura."
    else
        info "Python sin capacidades. Intentando aplicar (requiere sudo)..."

        if sudo -n true 2>/dev/null; then
            sudo setcap cap_net_raw,cap_net_admin=eip "$REAL_PY" || true

            if getcap "$REAL_PY" | grep -q "cap_net_admin,cap_net_raw=eip"; then
                ok "Capacidades aplicadas correctamente a Python."
            else
                warn "No se pudieron aplicar capacidades a Python."
                warn "Scapy/AsyncSniffer fallará sin sudo/root."
            fi
        else
            warn "No hay sudo sin contraseña."
            warn "Ejecuta manualmente:"
            warn "sudo setcap cap_net_raw,cap_net_admin=eip $REAL_PY"
        fi
    fi

    info "Estado final python caps: $(getcap "$REAL_PY" 2>/dev/null || echo 'none')"
fi

# -----------------------------
# [4/6] FREE PORT
# -----------------------------
section "[4/6] Liberando el puerto $PORT"

bash "$APP_PATH/free_port.sh" "$PORT"
ok "Puerto $PORT liberado o ya estaba libre."

# -----------------------------
# [5/6] PYTHON RUNTIME
# -----------------------------
section "[5/6] Verificando Gunicorn y Scapy en el VENV"

"$VENV_PYTHON" -m pip install --upgrade pip >/dev/null 2>&1 || true
"$VENV_PYTHON" -m pip install --upgrade gunicorn scapy
ok "Gunicorn y Scapy disponibles en el venv."

echo "============================================="
echo " [5/6] Verificando dependencias Python (en el VENV)"
echo "============================================="

set +e
"$VENV_PYTHON" - <<'PY'
import sys
missing=[]
for m in ("matplotlib",):
    try:
        __import__(m)
    except Exception:
        missing.append(m)
if missing:
    print("FALTAN:", ", ".join(missing))
    sys.exit(2)
print("[OK] matplotlib disponible (venv).")
PY
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "[WARN] matplotlib no está en el venv. Instalando con pip (venv)..."
  "$VENV_PYTHON" -m pip install --upgrade matplotlib
  echo "[OK] matplotlib instalado (pip/venv)."
fi

# -----------------------------
# [5.9/6] START nics_scenario_captures
# -----------------------------
section "[5.9/6] START nics_scenario_captures (background)"

LOG_DIR="$APP_PATH/app_core/infrastructure/ics_traffic/captures/full_scenario_captures/logs"
mkdir -p "$LOG_DIR"

sudo -n bash "$APP_PATH/nics_scenario_captures.sh" > "$LOG_DIR/scenario_captures.log" 2>&1 &
SCENARIO_CAPTURE_PID=$!
ok "nics_scenario_captures lanzado (PID=$SCENARIO_CAPTURE_PID)"

# -----------------------------
# [5.95/6] LOAD OPENSTACK CREDS
# -----------------------------
section "[5.95/6] Cargando credenciales OpenStack (admin-openrc.sh)"

OPENRC="$APP_PATH/admin-openrc.sh"
if [ -f "$OPENRC" ]; then
  set +u
  source "$OPENRC"
  set -u
  ok "OpenStack env cargado desde: $OPENRC"
else
  warn "No existe $OPENRC. Gunicorn arrancará SIN credenciales OS_*."
fi

if [ -z "${OS_AUTH_URL:-}" ]; then
  warn "OS_AUTH_URL está vacío. Revisa admin-openrc.sh o su export."
else
  ok "OS_AUTH_URL detectado."
fi

# -----------------------------
# [6/6] START SERVER
# -----------------------------
section "[6/6] Lanzando Servidor Forense (Gunicorn)"

cd "$APP_PATH" || exit 1

"$VENV_PYTHON" -m gunicorn \
    -w 4 \
    -b "0.0.0.0:$PORT" \
    --timeout "$TIMEOUT" \
    --log-level info \
    app:app

GUNICORN_RC=$?
info "Gunicorn finalizó con código: $GUNICORN_RC"
exit "$GUNICORN_RC"