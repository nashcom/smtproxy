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


create_env_file()
{
  if [ -e "$1" ]; then
    return
  fi

  cat > "$1" <<'EOF'
CONTAINER_NAME=smtproxy
CONTAINER_NETWORK=bridge
CONTAINER_CMD=docker
CONTAINER_HOSTNAME=
#EDITOR=vi
EOF
}

create_config_file()
{
  if [ -e "$1" ]; then
    return
  fi

  cat > "$1" <<'EOF'
SMTPROXY_LISTEN_ADDR=:25
SMTPROXY_TLS_LISTEN_ADDR=:465
SMTPROXY_METRICS_LISTEN_ADDR=:9100
SMTPROXY_ROUTING_MODE=local-first
SMTPROXY_LOCAL_UPSTREAMS=:25
SMTPROXY_REMOTE_UPSTREAMS=
SMTPROXY_REQUIRE_TLS=true
SMTPROXY_UPSTREAM_STARTTLS=true
SMTPROXY_UPSTREAM_REQUIRE_TLS=true
SMTPROXY_UPSTREAM_TLS=false
SMTPROXY_TLS13_ONLY=false
SMTPROXY_DNS_SERVERS=
SMTPROXY_UPSTREAM_TLS13_ONLY=false
SMTPROXY_SKIP_CERT_VALIDATION=false
SMTPROXY_SEND_XCLIENT=false
SMTPROXY_MAX_CONNECTIONS=1000
SMTPROXY_TRUSTED_ROOT_FILE=
SMTPROXY_CERT_FILE=/tls/tls.crt
SMTPROXY_KEY_FILE=/tls/tls.key
SMTPROXY_CERT_FILE2=
SMTPROXY_KEY_FILE2=
SMTPROXY_SERVER_NAME=
SMTPROXY_LOGLEVEL=verbose
SMTPROXY_HANDSHAKE_LOGLEVEL=none
SMTPROXY_MICROCA_CERT_FILE=
SMTPROXY_MICROCA_KEY_FILE=
SMTPROXY_MICROCA_CURVE_NAME=
EOF
}

usage()
{
  echo
  echo "Usage: $(basename $SCRIPT_NAME)"
  echo
  echo "Commands"
  echo "--------"
  echo
  echo "cfg         configure container"
  echo "env         configure container environment variables"
  echo "run         run or update container"
  echo "start       start container"
  echo "stop        stop container"
  echo "rm|remove   remove container"
  echo "log|logs    show container logs"
  echo "bash|sh     open shell in container" 
  echo
  echo "Options"
  echo "--------"
  echo
  echo "-wolfi      use Wolfi image"
  echo "-static     use Wolfi static image (very small and stripped down without shell)"
  echo
}


create_config()
{
  if [ ! -e "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
  fi

  create_env_file "$CONFIG_FILE"
  create_config_file "$CONTAINER_ENV_FILE"
}

edit_config()
{
  create_config
  "$EDITOR" "$CONFIG_FILE"
}

edit_env()
{
  create_config
  "$EDITOR" "$CONTAINER_ENV_FILE"
}

if [ -z "$CONTAINER_IMAGE" ]; then
  CONTAINER_IMAGE=nashcom/smtproxy
fi

CONFIG_DIR=~/.smtproxy
CONFIG_FILE=$CONFIG_DIR/config
CONTAINER_ENV_FILE=$CONFIG_DIR/env

# Source in config file

if [ -e "$CONFIG_FILE" ]; then
 . "$CONFIG_FILE"
fi

if [ -z "$CONTAINER_NAME" ]; then
  CONTAINER_NAME=smtproxy
fi  

if [ -z "$CONTAINER_NETWORK" ]; then
  CONTAINER_NETWORK=bridge
fi  

if [ -z "$CONTAINER_PORTS" ]; then
  CONTAINER_PORTS="-p 25:25 -p 465:465 -p 9100:9100"
fi  

if [ -z "$CONTAINER_CMD" ]; then
  CONTAINER_CMD=docker
fi  

if [ -z "$CONTAINER_HOSTNAME" ]; then
  CONTAINER_HOSTNAME=$(hostname -f)
fi  

if [ -z "$EDITOR" ]; then
  EDITOR=vi
fi


for a in "$@"; do

  p=$(echo "$a" | awk '{print tolower($0)}')

  case "$p" in

    cfg|env)
      COMMAND=$a
      ;;

    run|start|stop|rm|remove|logs|log|bash|sh)
      if [ ! "$CONFIG_FILE" .env ]; then
        log_error_exit "Please create the $CONFIG_FILE configuration file via 'env' command"
      fi
      COMMAND=$a
      ;;

    -host)
      CONTAINER_NETWORK=host
      ;;

    -static)
      CONTAINER_IMAGE="$CONTAINER_IMAGE:static"
      ;;

    -wolfi)
      CONTAINER_IMAGE="$CONTAINER_IMAGE:wolfi"
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

  cfg)
    edit_config
    ;;

  env)
    edit_env
    ;;

  run)

    if [ "$CONTAINER_STATUS" = "running" ]; then 
      "$CONTAINER_CMD" stop "$CONTAINER_NAME"
    fi

    if [ -n "$CONTAINER_STATUS" ]; then 
      "$CONTAINER_CMD" rm "$CONTAINER_NAME"
    fi

    "$CONTAINER_CMD" run -d --name "$CONTAINER_NAME" --hostname $CONTAINER_HOSTNAME $CONTAINER_PORTS --network "$CONTAINER_NETWORK" --cap-add=NET_BIND_SERVICE --env-file"$CONTAINER_ENV_FILE" $CONTAINER_VOLUMES "$CONTAINER_IMAGE"
    sleep 2
    "$CONTAINER_CMD" logs "$CONTAINER_NAME"
    ;;

  status)
    log "$CONTAINER_STATUS"
    ;;

  start)
    "$CONTAINER_CMD" start "$CONTAINER_NAME"
    ;;

  stop)
    "$CONTAINER_CMD" stop "$CONTAINER_NAME"
    ;;

  bash|sh)
    "$CONTAINER_CMD" exec -it "$CONTAINER_NAME" sh
    ;;

  root)
    "$CONTAINER_CMD" exec -it -u 0 "$CONTAINER_NAME" sh
    ;;

  logs|log)
    "$CONTAINER_CMD" logs $PARAM2 "$CONTAINER_NAME"
    ;;

  remove|rm)

    if [ "$CONTAINER_STATUS" = "running" ]; then 
      "$CONTAINER_CMD" stop "$CONTAINER_NAME"
    fi

    "$CONTAINER_CMD" rm "$CONTAINER_NAME"
    ;;

  *)
    log_error_exit "Invalid command [$COMMAND]"
    ;;

esac
