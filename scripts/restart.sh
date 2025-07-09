#!/bin/sh

podman-compose -p nftbk-server down
podman-compose -p nftbk-server up -d
