#!/bin/zsh
# Double-click launcher: runs netscan.py from the same folder.
# Launcher per doppio clic: avvia netscan.py dalla stessa cartella.
cd "$(dirname "$0")" || exit
python3 netscan.py || { echo; read -k 1 "?Error: press any key to close... "; }
exit
