#!/bin/bash
############################################################################
# Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
############################################################################

SCRIPT_NAME="$0"
SCRIPT_DIR=$(dirname $SCRIPT_NAME)
SMTPROXY_FILE="$SCRIPT_DIR/smtproxyctl.sh"
chmod 555 "$SMTPROXY_FILE"
echo
echo "Installing /usr/bin/smtproxyctl"
sudo cp -f "$SMTPROXY_FILE" "/usr/bin/smtproxyctl"
echo
