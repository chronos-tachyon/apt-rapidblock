#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
export PATH="$(pwd)/venv/bin:${PATH}"

if [ ! -x venv/bin/python ]; then
  rm -rf venv
  python3 -m venv venv
fi

if ! [ -e venv/touchfile -a venv/touchfile -nt requirements.txt ]; then
  pip install -r requirements.txt
  touch venv/touchfile
fi

declare -a pylint_argv
declare -a mypy_argv

if [ -n "${CI:+isset}" ]; then
  pylint_argv=( pylint --rcfile=.pylintrc-ci *.py )
  mypy_argv=( mypy --config-file=.mypy.ci.ini *.py )
else
  pylint_argv=( pylint --rcfile=.pylintrc *.py )
  mypy_argv=( mypy --config-file=.mypy.ini *.py )
fi

declare -i pylint_rc=0
echo "+ ${pylint_argv[*]}" >&2
"${pylint_argv[@]}" || pylint_rc=$?
echo "rc=${pylint_rc}" >&2

declare -i mypy_rc=0
echo "+ ${mypy_argv[*]}" >&2
"${mypy_argv[@]}" || mypy_rc=$?
echo "rc=${mypy_rc}" >&2

declare -i myrc=1
if [ $pylint_rc -eq 0 -a $mypy_rc -eq 0 ]; then
  myrc=0
fi
exit $myrc
