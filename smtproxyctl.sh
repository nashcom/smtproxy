#!/bin/bash
############################################################################
# Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
############################################################################

SCRIPT_NAME=$(readlink -f $0)
SCRIPT_DIR=$(dirname $SCRIPT_NAME)

ClearScreen()
{
  if [ "$DISABLE_CLEAR_SCREEN" = "yes" ]; then
    return 0
  fi

  clear
}

log_error()
{
  echo
  echo $@
  echo
}

log_error_exit()
{
  echo
  echo $@
  echo

  exit 1
}

log()
{
  echo
  echo $@
  echo
}

usage()
{
  echo
  echo
  echo "Usage: $(basename $SCRIPT_NAME) -image=<image name>"
  echo
}


if [ -z "$CONTAINER_IMAGE" ]; then
  CONTAINER_IMAGE=nashcom/smtproxy
fi


CONTAINER_NAME=smtproxy
CONTAINER_NETWORK=bridge
CONTAINER_PORTS="-p 25:25 -p 465:465"
CONTAINER_CMD=docker
COMMAND=

for a in "$@"; do

  p=$(echo "$a" | awk '{print tolower($0)}')

  case "$p" in

    run|stop|rm|remove|logs|log)
      COMMAND=$a
      ;;

    -host)
      CONTAINER_NETWORK=host
      ;;

    -static)
      CONTAINER_IMAGE="$CONTAINER_IMAGE/static"
      ;;

    -wolfi)
      CONTAINER_IMAGE="$CONTAINER_IMAGE/wolfi"
      ;;

    -image=*)
      CONTAINER_IMAGE=$(echo "$a" | cut -f2 -d= -s)
      ;;

    -f)
      PARAM2=$a
      ;;

    -h|/h|-\?|/\?|-help|--help|help|usage)
      usage
      exit 0
      ;;

    *)
      log_error_exit "Invalid parameter [$a]"
      ;;
  esac
done


CONTAINER_STATUS="$("$CONTAINER_CMD" inspect --format "{{ .State.Status }}" $CONTAINER_NAME 2>/dev/null)"
CONTAINER_CURRENT_IMAGE="$("$CONTAINER_CMD" inspect --format '{{ .Config.Image }}' "$CONTAINER_NAME" 2>/dev/null)"

case "$COMMAND" in

  "")
    echo
    echo "Image     : $CONTAINER_IMAGE"
    echo "Ctr Image : $CONTAINER_CURRENT_IMAGE"
    echo "Status    : $CONTAINER_STATUS"
    echo
    ;;

  run)

    if [ "$CONTAINER_STATUS" = "running" ]; then 
      "$CONTAINER_CMD" stop "$CONTAINER_NAME"
    fi

    if [ -n "$CONTAINER_STATUS" ]; then 
      "$CONTAINER_CMD" rm "$CONTAINER_NAME"
    fi

    "$CONTAINER_CMD" run -d --name "$CONTAINER_NAME" $CONTAINER_PORTS --network "$CONTAINER_NETWORK" --cap-add=NET_BIND_SERVICE --env-file .env -v ./tls:/tls "$CONTAINER_IMAGE"
    sleep 2

    ;;

  status)
    log "$CONTAINER_STATUS"
    ;;

  stop)
    "$CONTAINER_CMD" stop "$CONTAINER_NAME"
    ;;

  logs|log)
    "$CONTAINER_CMD" logs $PARAM2 "$CONTAINER_NAME"
    ;;

  remove|rm)
    "$CONTAINER_CMD" rm "$CONTAINER_NAME"
    ;;

  *)
    log_error_exit "Invalid command [$COMMAND]"
    ;;

esac

