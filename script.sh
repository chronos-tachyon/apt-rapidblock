#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
export PATH="$(pwd)/venv/bin:${PATH}"

if [ -z "${NOW:+isset}" ]; then
  sleep $((RANDOM % 3600))
fi

if [ ! -x venv/bin/python ]; then
  rm -rf venv
  python3 -m venv venv
fi

if ! [ -e venv/touchfile -a venv/touchfile -nt requirements.txt ]; then
  pip install -r requirements.txt
  touch venv/touchfile
fi

exec python script.py "$@"
