#!/bin/bash

docker run -d --rm --net=host  \
	-v $(pwd)/911builder:/911builder -v $(pwd)/meneja:/usr/src/app \
	--name meneja meneja:latest  \
	0.0.0.0 8080 https://meneja.gig.tech/callback  greenitglobe.team.operations \
	CvCJ6jm6ZZXwLwz3qWOWNsoUnN8yKEcP0KOFYZycIlJSaLhkAWal \
	https://docs.greenitglobe.com /911builder
