#!/bin/bash
set -e

if [ -z "${NOW:+isset}" ]; then
  sleep $((RANDOM % 3600))
fi

root="$(cd "$(dirname "$0")" && pwd -P)"

if [ ! -x "${root}/venv/bin/python" ]; then
  python3 -m venv "${root}/venv"
  "${root}/venv/bin/pip" install -r "${root}/requirements.txt"
fi

exec "${root}/venv/bin/python" "${root}/script.py" "$@"
