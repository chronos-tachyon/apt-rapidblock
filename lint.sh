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

readonly files=( ./*.py )
readonly pylintflags=( --rcfile=.pylintrc )

declare -i pylintrc=0
echo "+ pylint ${pylintflags[*]} ${files[*]}" >&2
pylint "${pylintflags[@]}" "${files[@]}" || pylintrc=$?
echo "rc=${pylintrc}" >&2

declare -i mypyrc=0
echo "+ mypy ${files[*]}" >&2
mypy "${files[@]}" || mypyrc=$?
echo "rc=${mypyrc}" >&2

declare -i myrc=1
if [ $pylintrc -eq 0 -a $mypyrc -eq 0 ]; then
  myrc=0
fi
exit $myrc
