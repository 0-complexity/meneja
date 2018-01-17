# Meneja
OpenvCloud environment manager

# installation
via Dockerfile

# arguments
```bash
usage: meneja.py [-h]
                    host port uri organization client_secret gitea
                    iso_template

Generate controller usb installer image

positional arguments:
  host           ip address to listen for requests
  port           port to listen for requests
  uri            Public callback uri for itsyou.online to this server
  organization   Itsyou.Online organization
  client_secret  Itsyou.Online client secret
  gitea          Url to gitea server
  iso_template   Path to iso template

optional arguments:
  -h, --help     show this help message and exit
```