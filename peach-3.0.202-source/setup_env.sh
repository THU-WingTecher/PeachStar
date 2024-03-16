#!/bin/sh

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

env="export LD_LIBRARY_PATH=$SCRIPTPATH:\$LD_LIBRARY_PATH"

if ! grep "$env" ~/.bashrc; then
echo "$env" >> ~/.bashrc
fi

env="export PATH=$SCRIPTPATH:\$PATH"
if ! grep "$env" ~/.bashrc; then
echo "$env" >> ~/.bashrc
fi

source ~/.bashrc
