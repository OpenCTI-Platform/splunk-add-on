#!/bin/bash
set -euo pipefail

# ===== Config =====
SITEPKG="./TA-opencti-add-on/bin/ta_opencti_add_on/aob_py3"
REQFILE="TA-opencti-add-on/lib/requirements.txt"

# Packages we never want inside the TA (trigger AArch64/UDP or heavy server deps)
BAN_PKGS=(
  pycti uvicorn websockets httptools uvloop watchfiles pydantic_core pydantic 
  prometheus_client aiohttp aiosignal async_timeout frozenlist multidict yarl
)

# Optional speedup modules we will force to pure-Python builds
PURE_PKGS=(pyyaml regex simplejson charset-normalizer)

say() { echo -e "\n>>> $*\n"; }

# 0) Ensure we are using the venv's python/pip
which python
python -m pip --version

# 1) Toolchain up-to-date (wheel/setuptools fixes many build isolation quirks)
say "Updating pip toolchain"
python -m pip install -U pip wheel setuptools

# 2) Pre-warm pure-Python build helpers (allow wheels; these are pure)
say "Pre-installing build helpers"
python -m pip install "setuptools_scm[toml]" importlib-metadata typing-extensions packaging tomli

# 3) Clean vendored site-packages and recreate
say "Cleaning vendored site-packages at $SITEPKG"
rm -rf "$SITEPKG" && mkdir -p "$SITEPKG"

# 4) Install base requirements (allow wheels & normal resolver)
say "Installing base requirements from $REQFILE"
python -m pip install --target "$SITEPKG" -r "$REQFILE" --upgrade

# 5) Remove banned/problematic packages if they snuck in (and any old copies)
say "Purging banned packages and old artifacts"
for pkg in "${BAN_PKGS[@]}"; do
  rm -rf "$SITEPKG/$pkg" "$SITEPKG"/${pkg/-/_}-*dist-info "$SITEPKG"/${pkg/-/_}"*.dist-info" 2>/dev/null || true
  rm -rf "$SITEPKG"/bin 2>/dev/null || true
done

# 6) Force pure-Python builds for speedup-prone libs (no deps to avoid dragging binaries)
say "Forcing pure-Python builds for: ${PURE_PKGS[*]}"
python -m pip install --target "$SITEPKG" --no-binary pyyaml,regex,simplejson,charset-normalizer --no-deps --upgrade \
  ${PURE_PKGS[@]}

# 7) Belt & suspenders: strip any native extensions
say "Stripping native .so/.pyd if any remain"
find "$SITEPKG" -type f \( -name '*.so' -o -name '*.pyd' \) -print -delete || true

# 8) Final sanity check
say "Verifying no native artifacts remain"
if find "$SITEPKG" -type f \( -name '*.so' -o -name '*.pyd' \) | grep -q .; then
  echo "ERROR: Native binaries still present in $SITEPKG — check dependencies." >&2
  exit 2
fi

# 9) Confirm removal of UDP prometheus client if present
rm -rf "$SITEPKG/prometheus_client" || true

say "Done. Vendored libs are pure-Python and AppInspect-safe."