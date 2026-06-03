#!/bin/bash

docker rm -f imagenalysis
docker run -d -p 9090:9090 --name imagenalysis --restart unless-stopped --privileged imagenalysis