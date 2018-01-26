#!/usr/bin/python3
"""
This program allows an operator to generate a usb stick image with
which he can boot and install the os on the 3 controller nodes.
"""
import os
import tempfile
from io import BytesIO, StringIO
from collections import defaultdict
import re
import tarfile
import hmac
import netaddr
import flask
from flask import jsonify, render_template, session, after_this_request, \
    send_file, request
from flask_itsyouonline import authenticated, configure
import requests
import yaml
import pycdlib
from Crypto.Cipher import AES
import jsonschema
import paramiko


REPO = re.compile("^env_.*")


app = flask.Flask(__name__, static_url_path='')  # pylint: disable=C0103
app.secret_key = os.urandom(24)


def run(args):  # pylint: disable=W0621
    """
    Main entry function
    """

    config = {
        'ROOT_URI': '/',
        'CLIENT_SECRET': args.client_secret,
        'args': args,
        'TEMPLATES_AUTO_RELOAD': True
    }
    app.config.update(config)
    configure(app, args.organization, args.client_secret, args.uri, '/callback',
              get_jwt=True, offline_access=True)
    app.jinja_env.auto_reload = True
    app.run(host=args.host, port=args.port)


@app.route("/", methods=["GET"])
@authenticated
def index():
    """
    Renders home page
    """
    # Get repos
    gitea_token = get_gitea_token()
    headers = dict(Authorization="token %s" % gitea_token)
    url = "%s/api/v1/user/repos" % app.config['args'].gitea
    orgs = defaultdict(list)
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    result = response.json()
    for repo in result:
        if not REPO.match(repo["name"]):
            continue
        orgs[repo["owner"]["username"]].append(repo["name"])
    return render_template('index.html', orgs=orgs, menu=Menu("Home"))


@app.route("/downloads", methods=["GET"])
@authenticated
def authkey():
    """
    Renders authentication key page
    """
    return render_template('downloads.html', menu=Menu("Downloads"))


@app.route("/download/authtoken", methods=["POST"])
@authenticated
def downloadtoken():
    """
    Generates download of auth token
    """
    payload = _generate_auth_token()
    return send_file(BytesIO(payload), as_attachment=True, attachment_filename="%s-token" % \
        session['iyo_user_info']['username'])


@app.route("/download/authkey", methods=["POST"])
@authenticated
def downloadauthkey():
    """
    Generates download of iso image with auth key
    """
    payload = _generate_auth_token()

    iso = pycdlib.PyCdlib()
    iso.new(joliet=3)
    iso.add_fp(BytesIO(payload), len(payload), '/JWT.;1', joliet_path="/jwt")
    buf = BytesIO()
    iso.write_fp(buf)
    iso.close()
    buf.seek(0)
    return send_file(buf, as_attachment=True, attachment_filename="%s-key.iso" % \
        session['iyo_user_info']['username'])


@app.route("/download/911", methods=["POST"])
@authenticated
def download911():
    """
    Generates download of iso image with auth key
    """
    payload = _generate_auth_token()

    # Generate files
    files = {"/etc/jwt": BytesIO(payload)}
    iso_filename = tempfile.mktemp()
    @after_this_request
    def _remove_file(response):
        if os.path.exists(iso_filename):
            os.remove(iso_filename)
        return response
    _generate_iso(files, iso_filename)
    return send_file(iso_filename, as_attachment=True, attachment_filename="911boot-%s.iso" % \
        session['iyo_user_info']['username'])


def _generate_auth_token():
    pad = lambda s: s.ljust(len(s) + 16 - len(s) % 16)
    jwt = pad(session['iyo_jwt'].encode("utf8"))
    password = pad(request.form["pwd"].encode("utf8"))

    cipher = AES.new(password, AES.MODE_ECB)
    encoded_jwt = cipher.encrypt(jwt)
    signature = hmac.new(password, encoded_jwt).digest()
    payload = signature + encoded_jwt
    return payload


@app.route("/environments", methods=["GET"])
@authenticated
def environments():
    """
    Renders home page
    """
    def make_gitea_call(uri, headers, params=None):
        """
        small method that addes uri's to the gitea base url and returns the json format of the reponse data.
        """
        url = "%s/api/v1/%s" % (app.config['args'].gitea, uri)
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()

    repos = []
    # Get repos
    gitea_token = get_gitea_token()
    headers = dict(Authorization="token %s" % gitea_token)
    # get user id to pass to search request
    uid = make_gitea_call('user/', headers)["id"]
    # paginate search repos to get all user repos as /user/repo cannot load itsyouonline repos
    url = "%s/api/v1/repos/search" % app.config['args'].gitea
    orgs = defaultdict(list)
    page = 1
    while True:
        result = make_gitea_call('repos/search', headers=headers, params={'uid': uid, 'limit': 50, 'page': page})
        if not result['data']:
            break
        page += 1
        repos += result['data']
    # search all repos for the env_ syntax
    for repo in repos:
        print(repo["name"])
        if not REPO.match(repo["name"]):
            continue
        orgs[repo["owner"]["username"]].append(repo["name"])
    return jsonify(orgs)


@app.route("/environment/<org>/<env>/config", methods=["GET"])
@authenticated
def environment_config(org, env):
    """
    return system-config yaml
    """
    config = _get_config(org, env)
    return jsonify(config)


@app.route("/manage/<org>/<env>", methods=["GET"])
@authenticated
def manage(org, env):
    """
    Renders home page
    """
    config = _get_config(org, env, True)
    return render_template('manage.html', org=org, env=env, config=config, menu=Menu(''))


@app.route("/validate/<org>/<env>", methods=["GET"])
@authenticated
def validate(org, env):
    """
    Validates the environment configuration
    """
    config = _get_config(org, env)
    response = requests.get('https://raw.githubusercontent.com/0-complexity/'
                            + 'openvcloud_installer/master/scripts/kubernetes/'
                            + 'config/config-validator.json')
    response.raise_for_status()
    schema = response.json()
    try:
        jsonschema.validate(config, schema)
    except Exception as error: # pylint: disable=W0703
        message = getattr(error, "message", str(type(error)))
        tree = ''
        for seq in getattr(error, "path", list()):
            if isinstance(seq, int):
                tree += '/<sequence {}>'.format(seq)
            else:
                tree += "/{}".format(seq)

        validator = getattr(error, "validator")
        if validator == 'type':
            message = '{msg} at {tree}'.format(msg=message, tree=tree)
        elif validator == 'required':
            missing_key = error.validator_value[-1] # pylint: disable=E1101
            message = ("Missing key in config at {tree}/{key}. Please check "
                       + "example config for reference.").format(key=missing_key, tree=tree)
        return jsonify(dict(result="fail", error=message))
    return jsonify(dict(result="ok"))


def _get_config(org, env, as_text=False):
    # Download yaml file from gitea
    gitea_token = get_gitea_token()
    url = "%s/api/v1/repos/%s/%s/raw/master/system-config.yaml?token=%s" \
        % (app.config['args'].gitea, org, env, gitea_token)
    with requests.get(url, stream=not as_text) as response:
        response.raise_for_status()
        if as_text:
            return response.text
        return yaml.load(response.content)


@app.route("/download/controller/config/<org>/<env>", methods=["GET"])
@authenticated
def download_config(org, env):
    """
    Generate and download usb stick image for a certain environment.
    """
    # Download yaml file from gitea
    config = _get_config(org, env)
    # Generate files
    files = generate_image(config)
    buf = BytesIO()
    with tarfile.open('config.tar', mode='w', fileobj=buf) as out:
        for name, contents in files.items():
            info = tarfile.TarInfo(os.path.basename(name))
            info.size = len(contents.getvalue())
            contents.seek(0)
            out.addfile(info, contents)
    buf.seek(0)
    return send_file(buf, as_attachment=True, attachment_filename="config.tar")


@app.route("/download/controller/usbinstall/<org>/<env>", methods=["GET"])
@authenticated
def download(org, env):
    """
    Generate and download usb stick image for a certain environment.
    """
    # Download yaml file from gitea
    gitea_token = get_gitea_token()
    url = "%s/api/v1/repos/%s/%s/raw/master/system-config.yaml?token=%s" \
        % (app.config['args'].gitea, org, env, gitea_token)
    with requests.get(url, stream=True) as response:
        response.raise_for_status()
        config = yaml.load(response.content)
    # Generate files
    files = generate_image(config)
    iso_filename = tempfile.mktemp()
    @after_this_request
    def _remove_file(response):
        if os.path.exists(iso_filename):
            os.remove(iso_filename)
        return response
    _generate_iso(files, iso_filename)
    return send_file(iso_filename, as_attachment=True, attachment_filename="%s.%s.iso" % (org, env))


def _generate_iso(files, iso_filename):
    iso = pycdlib.PyCdlib()
    iso.open(args.iso_template)
    try:
        for filename, contents in files.items():
            add_file(iso, filename, contents)
        iso.write(iso_filename)
    finally:
        iso.close()


def get_gitea_token():
    """
    Gets a gitea token for this user
    """
    gitea_token = session.get('gitea_token')
    if gitea_token:
        return gitea_token
    tokenurl = "%s/api/v1/token-by-jwt" % app.config['args'].gitea
    response = requests.post(tokenurl, data={"jwt": session['iyo_jwt']})
    response.raise_for_status()
    gitea_token = response.json()["sha1"]
    session['gitea_token'] = gitea_token
    return gitea_token


def add_file(iso, filename, contents):
    """
    Adds a file to the iso
    """
    directory = os.path.dirname(filename)
    path = ""
    for part in (p for p in directory.split("/") if p):
        path += "/" + part
        try:
            iso.get_entry(path)
        except pycdlib.pycdlibexception.PyCdlibInvalidInput:
            iso.add_directory(path.upper().replace('-', ''), rr_name=part, joliet_path=path)
    iso.add_fp(contents, len(contents.getvalue()), '%s.;1' % filename.upper().replace('-', '').replace('.',''),
               rr_name=os.path.basename(filename), joliet_path=filename)


def construct_ip(cidr, lsb):
    """
    Creates an ip adress from a cidr (eg 192.168.1.0/24) and the
    least significant byte (eg 12) => 192.168.1.12
    """
    net = netaddr.ip.IPNetwork(cidr)
    netbytes = list(net.network.words)
    netbytes[-1] = lsb
    return ".".join((str(b) for b in netbytes)).encode()


def generate_image(config):
    """
    Generates an usb key image based on the yaml configuration of a G8 environment.
    """
    scripts = dict()
    count = 0
    for controller in config['controller']['hosts']:
        # Add function to create directories
        script = BytesIO()

        # Add environment information
        script.write(b'HOSTNAME=%s\n' % controller['hostname'].encode())
        script.write(b'DOMAIN=%s\n' % config['environment']['subdomain'].encode())
        script.write(b'MASK=%s\n' % config['network']['management']['network']
                     .split('/', 1)[1].encode())
        script.write(b'MGMTVLAN=%s\n' % str(config['network']['management']['vlan']).encode())
        script.write(b'STORVLAN=%s\n' % str(config['network']['storage']['vlan']).encode())
        pubip, mask = controller['fallback']['ipaddress'].split('/', 1)
        script.write(b'PUBIP=%s\n' % pubip.encode())
        script.write(b'PUBMASK=%s\n' % mask.encode())
        script.write(b'PUBGW=%s\n' % controller['fallback']['gateway'].encode())
        script.write(b'PUBVLAN=%s\n' % str(config['network']['public']['vlan']).encode())
        script.write(b'MGMTIP=%s\n' % construct_ip(config['network']['management']['network'],
                                                   controller['ip-lsb']))
        script.write(b'IPMIIP=%s\n' % construct_ip(config['network']['ipmi']['network'],
                                                   controller['ip-lsb']))
        script.write(b'STORIP=%s\n' % construct_ip(config['network']['storage']['network'],
                                                   controller['ip-lsb']))
        script.write(b'UNTAGIP=%s\n' % construct_ip(config['network']['backplane']['network'],
                                                    controller['ip-lsb']))
        script.write(b'GIGPWD=%s\n' % str(config['environment']['password']).encode())
        count += 1
        scripts['/etc/ctrl-0%s' % count] = script
    pk = config['ssh']['private-key'].strip()
    buf = StringIO(pk)
    buf.seek(0)
    k = paramiko.RSAKey.from_private_key(buf)
    scripts['/etc/id_rsa.pub'] = BytesIO(k.get_base64().encode())
    return scripts


class Menu():  # pylint: disable=R0903
    """
    Site menu object
    """
    current = "not set"
    items = [
        dict(name="Home", url="/"),
        dict(name="Downloads", url="/downloads")
    ]

    def __init__(self, current):
        self.current = current

    def __iter__(self):
        return self.items.__iter__()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Generate controller usb installer image')   # pylint: disable=C0103
    parser.add_argument('host', type=str, help='ip address to listen for requests')
    parser.add_argument('port', type=int, help='port to listen for requests')
    parser.add_argument('uri', type=str, help='Public callback uri for itsyou.online to this server')
    parser.add_argument('organization', type=str, help='Itsyou.Online organization')
    parser.add_argument('client_secret', type=str, help='Itsyou.Online client secret')
    parser.add_argument('gitea', type=str, help='Url to gitea server')
    parser.add_argument('iso_template', type=str, help='Path to iso template')
    args = parser.parse_args()  # pylint: disable=C0103
    run(args)
