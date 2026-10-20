#!/usr/bin/env bash
# Instala una herramienta de CI con version y sha256 fijos (sin acciones de terceros).
# Uso: install-tool.sh <tofu|tflint|trivy|gitleaks|cargo-deny|cargo-audit|actionlint>...
# Si la herramienta ya esta en el PATH con la version pedida (p. ej. en el contenedor de
# desarrollo), no descarga nada.
set -euo pipefail

BIN_DIR="${INSTALL_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

GH="https://github.com"

# nombre|binario|version|url|sha256|miembro del archivo
spec() {
  case "$1" in
    tofu) echo "tofu|tofu|1.13.1|$GH/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_linux_amd64.tar.gz|378ada19d4bc70c43732004e8159be771b23b9a5afdf059e5f8a2b3fa2c70a69|tofu" ;;
    tflint) echo "tflint|tflint|0.64.0|$GH/terraform-linters/tflint/releases/download/v0.64.0/tflint_linux_amd64.zip|cca9d13e2e1d7a2c627af60ff899a3c9b74212899416aeb96ec764d2ef954537|tflint" ;;
    trivy) echo "trivy|trivy|0.75.0|$GH/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz|c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f|trivy" ;;
    gitleaks) echo "gitleaks|gitleaks|8.30.1|$GH/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz|551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb|gitleaks" ;;
    cargo-deny) echo "cargo-deny|cargo-deny|0.20.2|$GH/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz|9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f|cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny" ;;
    cargo-audit) echo "cargo-audit|cargo-audit|0.22.2|$GH/rustsec/rustsec/releases/download/cargo-audit%2Fv0.22.2/cargo-audit-x86_64-unknown-linux-musl-v0.22.2.tgz|7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428|cargo-audit-x86_64-unknown-linux-musl-v0.22.2/cargo-audit" ;;
    actionlint) echo "actionlint|actionlint|1.7.12|$GH/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz|8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8|actionlint" ;;
    *) echo "herramienta desconocida: $1" >&2; return 1 ;;
  esac
}

instalar() {
  local nombre bin version url sha miembro
  IFS='|' read -r nombre bin version url sha miembro < <(spec "$1")
  if command -v "$bin" >/dev/null 2>&1 && "$bin" --version 2>&1 | grep -qF "$version"; then
    echo "$nombre $version ya esta instalado"
    return 0
  fi
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  local archivo="$tmp/${url##*/}"
  curl -fsSL --retry 3 -o "$archivo" "$url"
  echo "$sha  $archivo" | sha256sum -c -
  case "$archivo" in
    *.zip) unzip -q "$archivo" "$miembro" -d "$tmp/x" ;;
    *) mkdir "$tmp/x" && tar -xzf "$archivo" -C "$tmp/x" "$miembro" ;;
  esac
  install -m 0755 "$tmp/x/$miembro" "$BIN_DIR/$bin"
  echo "$nombre $version instalado en $BIN_DIR"
}

for t in "$@"; do
  instalar "$t"
done

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$BIN_DIR" >> "$GITHUB_PATH"
fi
