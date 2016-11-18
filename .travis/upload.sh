#!/bin/bash
set -ev
if [ -n "$API_KEY" ]; then
  luarocks upload --api-key=$API_KEY --force $ROCKSPEC
fi
