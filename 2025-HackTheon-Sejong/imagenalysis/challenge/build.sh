#!/bin/sh

docker rm -f imagenalysis
docker rmi -f imagenalysis

docker build -t imagenalysis .
docker run -d --name imagenalysis imagenalysis tail -f /dev/null

docker rm -f imagenalysis