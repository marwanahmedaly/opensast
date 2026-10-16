#!/usr/bin/env bash
# One-command, user-local OpenSAST installation. No sudo, recursive submodules or scan.
set -euo pipefail
umask 077

fail() { printf 'OpenSAST installer: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: bash install.sh [--source DIR | --wheel FILE] [--offline --wheelhouse DIR]
                       [--prefix DIR] [--bin-dir DIR] [--ref REF] [--no-setup]
                       [-- SETUP_OPTIONS...]
With no source/wheel, installs the project's GitHub source at OPENSAST_REF/main.
Offline mode requires a local source/wheel and dependency wheels; it never clones.
Setup options are passed to opensast setup, e.g. --endpoint URL --model NAME.
EOF
}
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'This automatic installer supports Linux x86-64.'
command -v python3 >/dev/null || fail 'Install Python 3.11.8+ or Python 3.12+ first (including its venv module).'
python3 -c 'import sys,tarfile; assert sys.version_info >= (3,11) and hasattr(tarfile,"data_filter")' || fail 'Python 3.11.8+ or 3.12+ is required.'
install_prefix="${OPENSAST_INSTALL_DIR:-${HOME}/.local/share/opensast-app}"
install_bin="${OPENSAST_BIN_DIR:-${HOME}/.local/bin}"
install_source=''; install_wheel=''; install_wheelhouse=''; install_offline=0; install_no_setup=0
install_ref="${OPENSAST_REF:-main}"
setup_options=()
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --source|--wheel|--prefix|--bin-dir|--ref|--wheelhouse)
      (($# >= 2)) || fail "Missing value for $1"
      case "$1" in
        --source) install_source="$2";; --wheel) install_wheel="$2";; --prefix) install_prefix="$2";;
        --bin-dir) install_bin="$2";; --ref) install_ref="$2";; --wheelhouse) install_wheelhouse="$2";;
      esac
      shift 2;;
    --offline) install_offline=1; shift;;
    --no-setup) install_no_setup=1; shift;;
    --) shift; setup_options=("$@"); break;;
    *) fail "Unknown option: $1 (use --help)";;
  esac
done
[[ -z "$install_source" || -z "$install_wheel" ]] || fail 'Choose --source or --wheel, not both.'
if [[ -z "$install_source" && -z "$install_wheel" && -f "${BASH_SOURCE[0]:-}" ]]; then
  possible_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [[ -f "$possible_source/src/aisast/product/cli.py" && -f "$possible_source/hatch_build.py" ]]; then
    install_source="$possible_source"
  fi
fi
(( !install_offline )) || [[ -n "$install_source$install_wheel" && -d "$install_wheelhouse" ]] || fail 'Offline installation requires --source/--wheel and --wheelhouse DIR.'
python3 - "$install_prefix" <<'PYCODE'
import pathlib,shutil,sys
path=pathlib.Path(sys.argv[1]).expanduser()
while not path.exists(): path=path.parent
if shutil.disk_usage(path).free < 256*1024*1024:
    raise SystemExit('OpenSAST installer: at least 256 MiB free is required for the CLI environment. Engine/model setup requires additional space.')
PYCODE
mkdir -p "$install_prefix/envs" "$install_bin"
install_prefix="$(cd "$install_prefix" && pwd)"
install_bin="$(cd "$install_bin" && pwd)"
command -v flock >/dev/null || fail 'The Linux flock utility is required.'
exec 9>"$install_prefix/install.lock"
flock -n 9 || fail 'Another OpenSAST installation is running.'
if [[ -e "$install_bin/opensast" || -L "$install_bin/opensast" ]]; then
  [[ -L "$install_bin/opensast" && "$(readlink "$install_bin/opensast")" == "$install_prefix/current/bin/opensast" ]] || fail "Existing opensast executable at $install_bin/opensast; choose another --bin-dir to preserve it."
fi
install_work="$(mktemp -d "$install_prefix/.install.XXXXXX")"
install_env="$(mktemp -d "$install_prefix/envs/env.XXXXXX")"
install_committed=0
cleanup() {
  rm -rf -- "$install_work"
  if (( !install_committed )); then rm -rf -- "$install_env"; fi
}
trap cleanup EXIT
if [[ -z "$install_source$install_wheel" ]]; then
  command -v git >/dev/null || fail 'Git is required to install from GitHub; use --wheel for a release/offline installation.'
  printf 'Fetching OpenSAST %s. Private repositories require your Git credentials.\n' "$install_ref"
  git_options=()
  if command -v gh >/dev/null && [[ "${OPENSAST_REPOSITORY:-https://github.com/marwanahmedaly/opensast.git}" == https://github.com/* ]]; then
    git_options=(-c credential.helper= -c 'credential.helper=!gh auth git-credential')
  fi
  git "${git_options[@]}" clone --depth 1 --filter=blob:none --branch "$install_ref" \
    "${OPENSAST_REPOSITORY:-https://github.com/marwanahmedaly/opensast.git}" "$install_work/source"
  install_source="$install_work/source"
fi
python3 -m venv "$install_env" || fail 'Python venv is unavailable. Install your distribution’s python3-venv package.'
pip_options=(--disable-pip-version-check --no-cache-dir)
if ((install_offline)); then pip_options+=(--no-index --find-links "$install_wheelhouse"); fi
if [[ -n "$install_wheel" ]]; then
  install_wheel="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve())' "$install_wheel")"
  [[ -f "$install_wheel" ]] || fail 'Wheel file not found.'
  install_requirement="${install_wheel}[web,install]"
else
  install_source="$(cd "$install_source" && pwd)"
  [[ -f "$install_source/hatch_build.py" ]] || fail 'This source does not include the new packaged scanner installer.'
  install_requirement="${install_source}[web,install]"
fi
printf 'Installing OpenSAST in its own Python environment…\n'
"$install_env/bin/python" -m pip install "${pip_options[@]}" "$install_requirement"
# Promotion happens only after pip succeeds. Running processes keep their old environment.
if [[ -L "$install_prefix/current" ]]; then
  ln -sfn "$(readlink "$install_prefix/current")" "$install_prefix/previous"
fi
ln -s "$install_env" "$install_work/current"
mv -Tf "$install_work/current" "$install_prefix/current"
ln -sfn "$install_prefix/current/bin/opensast" "$install_bin/opensast"
install_committed=1
printf 'Installed: %s/opensast\n' "$install_bin"
case ":$PATH:" in
  *":$install_bin:"*) ;;
  *)
    # Keep one managed PATH line in the shell startup files, including paths with spaces.
    path_line="$(printf 'export PATH=%q:$PATH' "$install_bin") # OpenSAST installer"
    for profile_file in "$HOME/.profile" "$HOME/.bashrc"; do
      if ! grep -Fq '# OpenSAST installer' "$profile_file" 2>/dev/null; then
        printf '\n%s\n' "$path_line" >> "$profile_file"
      fi
    done
    printf 'Open a new terminal afterward to use opensast by name.\n';;
esac
if (( !install_no_setup )); then
  if ((install_offline)); then setup_options=(--offline "${setup_options[@]}"); fi
  if [[ -t 0 ]]; then
    "$install_bin/opensast" setup "${setup_options[@]}"
  elif [[ -r /dev/tty ]] && (exec </dev/tty) 2>/dev/null; then
    # curl | bash supplies the script on stdin; prompt from the terminal instead.
    "$install_bin/opensast" setup "${setup_options[@]}" </dev/tty
  else
    "$install_bin/opensast" setup --non-interactive "${setup_options[@]}"
  fi
fi
printf 'Updates preserve ~/.local/share/opensast (or OPENSAST_HOME). Old environments remain available for rollback.\n'
