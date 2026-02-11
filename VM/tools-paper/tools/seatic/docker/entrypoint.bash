#!/usr/bin/env bash

USER_ID=${LOCAL_USER_ID:-9001}
USER_NAME=dockeruser

echo "Starting with UID : $USER_ID"
usermod --uid $USER_ID $USER_NAME
export HOME=/home/$USER_NAME

exec gosu $USER_NAME "$@"
