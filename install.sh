#!/usr/bin/env bash
# Instala e controla a telemetria local sem apagar estado ou relatórios.
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
DEFAULT_WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly DEFAULT_WORKSPACE
readonly DEFAULT_STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/tool-telemetry"
readonly DEFAULT_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
readonly DEFAULT_RUNTIME_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/tool-telemetry"

action="install"
dry_run=0
new_run=0
workspace_dir="$DEFAULT_WORKSPACE"
state_dir="$DEFAULT_STATE_DIR"
unit_dir="$DEFAULT_UNIT_DIR"
runtime_dir="$DEFAULT_RUNTIME_DIR"
python_bin="${PYTHON_BIN:-python3}"
home_dir="${HOME%/}"
window_start_utc="not-started"
finalize_at_utc="2099-01-01 00:00:00 UTC"
window_resumed=0
state_window_present=0
timer_window_present=0
system_path=""
unset_environment=""
exclude_session_paths=()

usage() {
  cat <<'EOF'
Uso: ./install.sh [install|start|status|logs|stop] [opções]

Opções:
  --workspace DIRETÓRIO  Raiz do repositório a monitorar.
  --state-dir DIRETÓRIO  Diretório privado e persistente de estado.
  --unit-dir DIRETÓRIO   Diretório das unidades systemd de usuário.
  --runtime-dir DIRETÓRIO Diretório privado da cópia executável.
  --python CAMINHO       Interpretador Python a executar.
  --exclude-session ARQUIVO
                        Exclui uma sessão antes da primeira amostra; repetível.
  --new-run              Inicia em state-dir novo e substitui timer parado.
  --dry-run              Mostra as ações; não escreve nem ativa unidades.
  -h, --help             Mostra esta ajuda.
EOF
}

die() {
  printf 'erro: %s\n' "$*" >&2
  exit 1
}

run() {
  if (( dry_run )); then
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

require_safe_path() {
  local label="$1"
  local path="$2"
  [[ "$path" = /* ]] || die "$label deve ser um caminho absoluto"
  [[ "$path" != "/" ]] || die "$label não pode ser /"
  [[ "$path" != *$'\n'* ]] || die "$label não pode conter quebra de linha"
  [[ "$path" != *[[:space:]]* ]] || die "$label não pode conter espaço em branco"
}

require_runtime() {
  command -v systemctl >/dev/null || die 'systemctl não foi encontrado'
  date -u -d '@0' '+%Y-%m-%d %H:%M:%S UTC' >/dev/null 2>&1 || die 'date compatível com UTC e -d é necessário'
  command -v "$python_bin" >/dev/null || die "Python não encontrado: $python_bin"
}

require_runtime_source() {
  [[ -f "$SCRIPT_DIR/tool_telemetry.py" ]] || die "coletor ausente: $SCRIPT_DIR/tool_telemetry.py"
  [[ -f "$SCRIPT_DIR/README.md" ]] || die "README ausente: $SCRIPT_DIR/README.md"
}

require_installed_runtime() {
  [[ -r "$runtime_dir/tool_telemetry.py" ]] || die "runtime ausente: $runtime_dir/tool_telemetry.py; execute install primeiro"
  [[ -r "$runtime_dir/README.md" ]] || die "runtime incompleto: $runtime_dir/README.md; execute install primeiro"
}

require_user_manager() {
  if ! systemctl --user show-environment >/dev/null 2>&1; then
    die 'o gerenciador systemd de usuário não está disponível; inicie uma sessão de usuário com systemd e tente novamente'
  fi
}

escape_sed() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

append_system_path() {
  local directory="$1"
  require_safe_path 'diretório no PATH' "$directory"
  case ":$system_path:" in
    *":$directory:"*) return ;;
  esac
  if [[ -n "$system_path" ]]; then
    system_path+=":"
  fi
  system_path+="$directory"
}

append_command_directory() {
  local executable="$1"
  local executable_path
  executable_path="$(command -v "$executable" 2>/dev/null || true)"
  [[ -n "$executable_path" ]] || return 0
  append_system_path "$(dirname -- "$executable_path")"
}

build_system_path() {
  system_path=""
  append_system_path "$HOME/.local/bin"
  append_system_path "$HOME/.local/share/pnpm/bin"
  append_system_path "$HOME/.bun/bin"
  append_command_directory node
  append_command_directory sc
  append_command_directory rg
  append_system_path "/home/linuxbrew/.linuxbrew/bin"
  append_system_path "/usr/local/bin"
  append_system_path "/usr/bin"
  append_system_path "/bin"
}

build_unset_environment() {
  local environment_line variable_name
  unset_environment=""
  while IFS= read -r environment_line; do
    variable_name="${environment_line%%=*}"
    case "$variable_name" in
      HOME|PATH|PYTHONUNBUFFERED|STATE_DIR|WORKSPACE_DIR|XDG_RUNTIME_DIR|OPENBLAS_NUM_THREADS|OMP_NUM_THREADS|MKL_NUM_THREADS|NUMEXPR_NUM_THREADS) continue ;;
    esac
    [[ "$variable_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -n "$unset_environment" ]]; then
      unset_environment+=" "
    fi
    unset_environment+="$variable_name"
  done < <(systemctl --user show-environment)
}

is_utc_timestamp() {
  local timestamp="$1"
  [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}\ UTC$ ]] || return 1
  date -u -d "$timestamp" +%s >/dev/null 2>&1
}

load_state_window() {
  local state_file="$state_dir/state.json"
  local state_window
  state_window_present=0
  [[ -e "$state_file" ]] || return 0
  [[ -r "$state_file" ]] || die "estado não pode ser lido: $state_file"
  state_window="$("$python_bin" -c '
import datetime as dt
import json
import sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
start = dt.datetime.fromisoformat(state["window_start"])
end = dt.datetime.fromisoformat(state["window_end"])
if start.tzinfo is None or end.tzinfo is None or (end - start).total_seconds() != 168 * 60 * 60:
    raise ValueError("janela inválida")
print(start.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
print(end.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
' "$state_file")" || die "janela de estado inválida: $state_file"
  window_start_utc="$(printf '%s\n' "$state_window" | sed -n '1p')"
  finalize_at_utc="$(printf '%s\n' "$state_window" | sed -n '2p')"
  is_utc_timestamp "$window_start_utc" || die "início de estado inválido: $state_file"
  is_utc_timestamp "$finalize_at_utc" || die "fim de estado inválido: $state_file"
  state_window_present=1
}

load_timer_window() {
  local installed_timer="$unit_dir/tool-telemetry-finalize.timer"
  local stored_start stored_finalize
  timer_window_present=0
  [[ -e "$installed_timer" ]] || return 0
  [[ -r "$installed_timer" ]] || die "timer não pode ser lido: $installed_timer"
  stored_start="$(sed -n 's/^# TelemetryWindowStartUTC=//p' "$installed_timer" | head -n 1)"
  stored_finalize="$(sed -n 's/^# TelemetryFinalizeAtUTC=//p' "$installed_timer" | head -n 1)"
  if [[ "$stored_start" == "not-started" && "$stored_finalize" == "2099-01-01 00:00:00 UTC" ]]; then
    return
  fi
  is_utc_timestamp "$stored_start" || die "início do timer inválido: $installed_timer"
  is_utc_timestamp "$stored_finalize" || die "fim do timer inválido: $installed_timer"
  window_start_utc="$stored_start"
  finalize_at_utc="$stored_finalize"
  timer_window_present=1
}

require_matching_windows() {
  local state_start="$window_start_utc"
  local state_finalize="$finalize_at_utc"
  load_timer_window
  (( timer_window_present )) || die 'timer de finalização ausente para a janela existente'
  [[ "$state_start" == "$window_start_utc" && "$state_finalize" == "$finalize_at_utc" ]] || die "state e timer divergem; nenhuma execução foi iniciada"
  window_start_utc="$state_start"
  finalize_at_utc="$state_finalize"
}

prepare_window_for_install() {
  load_state_window
  local state_start="$window_start_utc"
  local state_finalize="$finalize_at_utc"
  load_timer_window
  if (( state_window_present && timer_window_present )); then
    [[ "$state_start" == "$window_start_utc" && "$state_finalize" == "$finalize_at_utc" ]] || die 'state e timer divergem; instalação não alterou a janela'
    window_start_utc="$state_start"
    finalize_at_utc="$state_finalize"
    printf 'janela existente preservada: início %s; finalização %s\n' "$window_start_utc" "$finalize_at_utc"
  elif (( state_window_present )); then
    window_start_utc="$state_start"
    finalize_at_utc="$state_finalize"
    printf 'estado existente preservado; timer será renderizado sem ativação.\n'
  elif (( timer_window_present )); then
    die 'timer de finalização existe sem state; instalação recusada para não criar execução divergente'
  fi
}

prepare_window_for_start() {
  local now_epoch finalize_epoch
  load_state_window
  if (( new_run )); then
    (( ! state_window_present )) || die '--new-run exige --state-dir sem state.json existente'
    if systemctl --user is-active --quiet tool-telemetry-sample.timer tool-telemetry-finalize.timer \
      || systemctl --user is-enabled --quiet tool-telemetry-sample.timer tool-telemetry-finalize.timer; then
      die '--new-run exige os timers parados e desabilitados; execute stop primeiro'
    fi
    window_resumed=0
    printf 'nova execução isolada será inicializada; estado anterior não será apagado.\n'
    return
  fi
  if (( state_window_present )); then
    require_matching_windows
    now_epoch="$(date -u +%s)"
    finalize_epoch="$(date -u -d "$finalize_at_utc" +%s)"
    (( finalize_epoch > now_epoch )) || die "janela existente expirou em $finalize_at_utc; não foi reinicializada"
    window_resumed=1
    printf 'janela existente preservada: início %s; finalização %s\n' "$window_start_utc" "$finalize_at_utc"
    return
  fi
  load_timer_window
  (( ! timer_window_present )) || die 'timer de finalização existe sem state; start recusado para não criar execução divergente'
  window_resumed=0
  printf 'nova execução será inicializada antes de renderizar o timer.\n'
}

install_units() {
  run mkdir -p -- "$workspace_dir/docs"
  local source_file destination_file temp_file
  local escaped_project escaped_workspace escaped_state escaped_python escaped_home escaped_runtime escaped_window_start escaped_finalize_at escaped_system_path escaped_unset_environment

  escaped_project="$(escape_sed "$SCRIPT_DIR")"
  escaped_workspace="$(escape_sed "$workspace_dir")"
  escaped_state="$(escape_sed "$state_dir")"
  escaped_python="$(escape_sed "$python_bin")"
  escaped_home="$(escape_sed "$home_dir")"
  escaped_runtime="$(escape_sed "$runtime_dir")"
  escaped_window_start="$(escape_sed "$window_start_utc")"
  escaped_finalize_at="$(escape_sed "$finalize_at_utc")"
  escaped_system_path="$(escape_sed "$system_path")"
  escaped_unset_environment="$(escape_sed "$unset_environment")"
  run mkdir -p -- "$unit_dir"

  for source_file in "$SCRIPT_DIR"/systemd/tool-telemetry-*; do
    [[ -f "$source_file" ]] || die "unidade ausente: $source_file"
    destination_file="$unit_dir/$(basename -- "$source_file")"
    temp_file="$destination_file.tmp.$$"
    if (( dry_run )); then
      printf '+ instalar %q em %q\n' "$source_file" "$destination_file"
      continue
    fi
    sed \
      -e "s|@PROJECT_DIR@|$escaped_project|g" \
      -e "s|@WORKSPACE_DIR@|$escaped_workspace|g" \
      -e "s|@STATE_DIR@|$escaped_state|g" \
      -e "s|@PYTHON_BIN@|$escaped_python|g" \
      -e "s|@HOME_DIR@|$escaped_home|g" \
      -e "s|@RUNTIME_DIR@|$escaped_runtime|g" \
      -e "s|@WINDOW_START_UTC@|$escaped_window_start|g" \
      -e "s|@FINALIZE_AT_UTC@|$escaped_finalize_at|g" \
      -e "s|@SYSTEM_PATH@|$escaped_system_path|g" \
      -e "s|@UNSET_ENVIRONMENT@|$escaped_unset_environment|g" \
      -- "$source_file" > "$temp_file"
    chmod 0600 -- "$temp_file"
    mv -f -- "$temp_file" "$destination_file"
  done

  run systemctl --user daemon-reload
}

install_runtime() {
  local source_file destination_file temporary_file
  require_runtime_source
  run mkdir -p -- "$runtime_dir"
  run chmod 0700 -- "$runtime_dir"
  for source_file in "$SCRIPT_DIR/tool_telemetry.py" "$SCRIPT_DIR/README.md"; do
    destination_file="$runtime_dir/$(basename -- "$source_file")"
    temporary_file="$destination_file.tmp.$$"
    run install -m 0600 -- "$source_file" "$temporary_file"
    run mv -f -- "$temporary_file" "$destination_file"
  done
}

initialize() {
  run mkdir -p -- "$state_dir"
  run "$python_bin" "$runtime_dir/tool_telemetry.py" --state-dir "$state_dir" --workspace "$workspace_dir" init
}

exclude_monitoring_sessions() {
  local session_path
  for session_path in "${exclude_session_paths[@]}"; do
    [[ "$session_path" = /* ]] || die 'a sessão excluída deve usar caminho absoluto'
    [[ "$session_path" != *$'\n'* ]] || die 'o caminho da sessão excluída não pode conter quebra de linha'
    [[ -f "$session_path" && -r "$session_path" ]] || die "sessão excluída não pode ser lida: $session_path"
    run "$python_bin" "$runtime_dir/tool_telemetry.py" \
      --state-dir "$state_dir" \
      --workspace "$workspace_dir" \
      exclude-session --path "$session_path"
  done
}

start_monitoring() {
  if (( window_resumed )); then
    printf 'janela ativa retomada; init e coleta inicial não foram repetidos.\n'
  else
    initialize
    if (( dry_run )); then
      exclude_monitoring_sessions
      printf 'dry-run: state não foi criado; OnCalendar não foi renderizado.\n'
      return
    fi
    load_state_window
    (( state_window_present )) || die 'init não produziu window_start/window_end'
    printf 'nova janela do state: início %s; finalização %s\n' "$window_start_utc" "$finalize_at_utc"
  fi
  exclude_monitoring_sessions
  install_units
  run systemctl --user enable --now tool-telemetry-sample.timer tool-telemetry-finalize.timer
  if (( ! window_resumed )); then
    run systemctl --user start tool-telemetry-sample.service
  fi
}

status_monitoring() {
  run systemctl --user --no-pager status tool-telemetry-sample.timer tool-telemetry-finalize.timer
  run "$python_bin" "$runtime_dir/tool_telemetry.py" --state-dir "$state_dir" --workspace "$workspace_dir" status
}

logs_monitoring() {
  run journalctl --user --no-pager -u tool-telemetry-sample.service -u tool-telemetry-finalize.service
}

stop_monitoring() {
  run systemctl --user disable --now tool-telemetry-sample.timer tool-telemetry-finalize.timer
}

while (( $# )); do
  case "$1" in
    install|start|status|logs|stop)
      action="$1"
      ;;
    --workspace)
      (( $# >= 2 )) || die 'faltou valor para --workspace'
      workspace_dir="$2"
      shift
      ;;
    --state-dir)
      (( $# >= 2 )) || die 'faltou valor para --state-dir'
      state_dir="$2"
      shift
      ;;
    --unit-dir)
      (( $# >= 2 )) || die 'faltou valor para --unit-dir'
      unit_dir="$2"
      shift
      ;;
    --runtime-dir)
      (( $# >= 2 )) || die 'faltou valor para --runtime-dir'
      runtime_dir="$2"
      shift
      ;;
    --python)
      (( $# >= 2 )) || die 'faltou valor para --python'
      python_bin="$2"
      shift
      ;;
    --exclude-session)
      (( $# >= 2 )) || die 'faltou valor para --exclude-session'
      exclude_session_paths+=("$2")
      shift
      ;;
    --new-run)
      new_run=1
      ;;
    --dry-run)
      dry_run=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "argumento desconhecido: $1"
      ;;
  esac
  shift
done

workspace_dir="$(cd -- "$workspace_dir" && pwd -P)"
state_dir="${state_dir%/}"
unit_dir="${unit_dir%/}"
runtime_dir="${runtime_dir%/}"
require_safe_path 'diretório de estado' "$state_dir"
require_safe_path 'diretório de unidades' "$unit_dir"
require_safe_path 'diretório de runtime' "$runtime_dir"
require_safe_path 'HOME' "$home_dir"
require_runtime
require_user_manager
build_system_path
build_unset_environment

if (( ${#exclude_session_paths[@]} > 0 )) && [[ "$action" != "start" ]]; then
  die '--exclude-session só pode ser usado com start'
fi
if (( new_run )) && [[ "$action" != "start" ]]; then
  die '--new-run só pode ser usado com start'
fi

case "$action" in
  install)
    install_runtime
    prepare_window_for_install
    install_units
    printf 'instalação concluída sem criar execução. Inicie com: %s start\n' "$0"
    ;;
  start)
    require_installed_runtime
    prepare_window_for_start
    start_monitoring
    ;;
  status)
    require_installed_runtime
    status_monitoring
    ;;
  logs)
    logs_monitoring
    ;;
  stop)
    stop_monitoring
    printf 'temporizadores parados; estado e relatórios foram preservados.\n'
    ;;
esac
