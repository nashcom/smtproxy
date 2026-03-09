#!/bin/bash
############################################################################
# Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
############################################################################

CONTAINER_IMAGE=nashcom/smtproxy
CONTAINER_CMD=docker
DOCKER_FILE=container/dockerfile
IMAGE_DESCRIPTION=Alpine


print_delim()
{
  echo "--------------------------------------------------------------------------------"
}

header()
{
  echo
  print_delim
  echo "$1"
  print_delim
  echo
}


log()
{
  echo
  echo $@
  echo
}

print_runtime()
{
  hours=$((SECONDS / 3600))
  seconds=$((SECONDS % 3600))
  minutes=$((seconds / 60))
  seconds=$((seconds % 60))
  h=""; m=""; s=""
  if [ ! $hours = "1" ] ; then h="s"; fi
  if [ ! $minutes = "1" ] ; then m="s"; fi
  if [ ! $seconds = "1" ] ; then s="s"; fi
  if [ ! $hours = 0 ] ; then echo "Completed in $hours hour$h, $minutes minute$m and $seconds second$s"
  elif [ ! $minutes = 0 ] ; then echo "Completed in $minutes minute$m and $seconds second$s"
  else echo "Completed in $seconds second$s"; fi
  echo
}


case "$1" in

  "")
    ;;

  -static)
    DOCKER_FILE=container/dockerfile_static
    CONTAINER_IMAGE=$CONTAINER_IMAGE:static
    IMAGE_DESCRIPTION="Chainguard Static"
    ;;

  -wolfi)
    DOCKER_FILE=container/dockerfile_wolfi
    CONTAINER_IMAGE=$CONTAINER_IMAGE:wolfi
    IMAGE_DESCRIPTION="Chainguard Wolfi"
    ;;

  *)
    echo "Invalid parameter [$1]"
    exit 1
    ;;
esac

export BUILDAH_FORMAT=1

header "Building smtproxy image - $IMAGE_DESCRIPTION / $CONTAINER_IMAGE"

"$CONTAINER_CMD" build --no-cache -f "$DOCKER_FILE" -t "$CONTAINER_IMAGE" .

echo
print_runtime
echo
