#!/usr/bin/env bash

echo 'Setup Started'
echo

set -x
# Make sure we have nano and unzip.
sudo apt-get update

pip install art huepy argparse

echo 'Setup Completed'
