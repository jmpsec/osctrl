#!/usr/bin/env bash
#
# Helper to update all go.mod files with the latest commit of osctrl

# If more than one parameter, show usage
if [ $# -gt 1] ; then
  echo "Usage: $0 <module_directory>"
  exit 1
fi

declare -a MODULES=()

# If one parameter, that is the module directory
if [ $# -eq 1 ] ; then
  echo "[+] Using module $1"
  MODULES+=( "$1" )
fi

# If no parameters, recursively find all go.mod files
if [ $# -eq 0 ] ; then
  echo "[+] Finding all go.mod files..."
  MODULES+=( $(find . -name "go.mod" | sed 's/\/go.mod//g' | grep -v "\.$") )
  echo "[+] Found ${#MODULES[@]} modules"
fi

# Iterate over all modules
for module in "${MODULES[@]}"
do
  echo "[+] Updating module $module"
  cd "$module" || exit 1
  go get -u
  cd - || exit 1
done

echo "[+] Done"
