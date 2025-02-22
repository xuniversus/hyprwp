#!/bin/bash

set -ex

handle() {
  case $1 in
    monitoraddedv2)
      ./linux-wallpaperengine --screen-root "${MONITORID}" \
      "${adir}" \
      "$(ls -d "${wpdir}"/* | shuf -n 1)" &
      monproc["${MONITORNAME}"]="$!"
      ;;
    monitorremoved)
      if [ "$(ps -p "${monproc["${MONITORNAME}"]}" -o cmd=)" -eq "linux-wallpaper" ]; then \
        kill "${monproc["${MONITORNAME}"]}"
      fi
      ;;
  esac
}

main() {
  adir=""
  wpdir=""
  declare -A monproc

  if test $# != 0; then
    echo >&2 "Need at least the wallpaper directory"
    exit 1
  fi

  while test $# != 0; do
    case $1 in
      --assets|-a)
        adir="--assets-dir $2"
        shift 2
        ;;
      --wallpapers|-w)
        wpdir="$2"
        shift 2
        ;;
      *)
        echo >&2 "Unknown flags"
        exit 1
        ;;
    esac
  done  

  socat -U - UNIX-CONNECT:$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket2.sock | \
        while read -r line; do handle "$line"; done
}

main "$@"
