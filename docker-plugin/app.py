from flask import Flask, request
from readerwriterlock.rwlock import RWLockFair as Lock
from typing import Optional
import shelve

from privkeys import derive_privkey

app = Flask(__name__)

db_lock = Lock()
db = shelve.open('network-db', writeback=True)
if 'n' not in db: db['n'] = {}  # initialize database

def docker_err(err: str):
  """Format an error string to return to Docker."""
  return {'Err': err}

def install_if(network: dict, endpoint: dict) -> Optional[str]:
  """Create and configure WireGuard interface."""
  IFPREFIX = 'bst'
  import subprocess, tempfile
  ifname = (IFPREFIX + endpoint['id'])[0:15]
  try:
    subprocess.run(['ip', 'link', 'add', 'name', ifname, 'type', 'wireguard']).check_returncode()
  except subprocess.CalledProcessError:
    return None
  subprocess.run(['ip', 'link'])
  subprocess.run(['wg'])
  privkey = derive_privkey(network['Seed'], endpoint['Address'], network['Additional'])
  conf = f"""
[Interface]
PrivateKey = {privkey}

[Peer]
PublicKey = {network['PeerKey']}
AllowedIPs = 0.0.0.0/0
Endpoint = {network['Peer']}
PersistentKeepalive = 25
""".encode('utf8')
  with tempfile.NamedTemporaryFile() as f:
    f.write(conf)
    f.flush()
    try:
      subprocess.run(['wg', 'setconf', ifname, f.name]).check_returncode()
    except subprocess.CalledProcessError:
      return None
  subprocess.run(['ip', 'link'])
  subprocess.run(['wg'])
  return ifname

def uninstall_if(ifname: str):
  """Destroy WireGuard interface."""
  import subprocess
  subprocess.run(['ip', 'link', 'del', ifname])

@app.post('/Plugin.Activate')
def activate():
  return {'Implements': ['NetworkDriver']}

@app.post('/NetworkDriver.GetCapabilities')
def capabilities():
  return {'Scope': 'local', 'ConnectivityScope': 'local'} 

# todo: better checking. return an error if any of the options have bad values
@app.post('/NetworkDriver.CreateNetwork')
def create_network():
  req = request.get_json(force=True)
  copts = req['Options']['com.docker.network.generic']
  entry = {}
  entry['Peer'] = copts['io.bestov.wg.peer']
  entry['PeerKey'] = copts['io.bestov.wg.peerkey']
  entry['Seed'] = copts['io.bestov.wg.seed']
  entry['Additional'] = copts['io.bestov.wg.additional']
  entry['id'] = req['NetworkID']
  entry['e'] = {}
  l = db_lock.gen_wlock()
  while not l.acquire(): pass
  try:
    db['n'][req['NetworkID']] = entry
  except:
    return docker_err('failed to serialize')
  finally:
    db.sync()
    l.release()
  return {}

@app.post('/NetworkDriver.DeleteNetwork')
def delete_network():
  req = request.get_json(force=True)
  l = db_lock.gen_wlock()
  while not l.acquire(): pass
  try:
    if req['NetworkID'] in db['n']:
      del db['n'][req['NetworkID']]
    else:
      return docker_err('unknown network')
  except:
    return docker_err('failed to serialize')
  finally:
    db.sync()
    l.release()
  return {}

@app.post('/NetworkDriver.CreateEndpoint')
def create_endpoint():
  req = request.get_json(force=True)
  entry = {}
  entry['Address'] = req['Interface']['Address']
  entry['id'] = req['EndpointID']
  entry['joined'] = None
  l = db_lock.gen_wlock()
  while not l.acquire(): pass
  try:
    db['n'][req['NetworkID']]['e'][req['EndpointID']] = entry
  except:
    return docker_err('failed to serialize')
  finally:
    db.sync()
    l.release()
  return {'Interface': {}}

@app.post('/NetworkDriver.EndpointOperInfo')
def operinfo_endpoint():
  return {'Value': {}}

@app.post('/NetworkDriver.DeleteEndpoint')
def delete_endpoint():
  req = request.get_json(force=True)
  l = db_lock.gen_wlock()
  while not l.acquire(): pass
  try:
    if req['NetworkID'] in db['n']:
      if req['EndpointID'] in db['n'][req['NetworkID']]['e']:
        del db['n'][req['NetworkID']]['e'][req['EndpointID']]
      else:
        return docker_err('unknown endpoint')
    else:
      return docker_err('unknown network')
  except:
    return docker_err('failed to serialize')
  finally:
    db.sync()
    l.release()
  return {}

@app.post('/NetworkDriver.Join')
def join():
  req = request.get_json(force=True)
  l = db_lock.gen_rlock()
  while not l.acquire(): pass
  try:
    network = db['n'][req['NetworkID']]
    endpoint = db['n'][req['NetworkID']]['e'][req['EndpointID']]
  except:
    return docker_err('failed to get endpoint')
  finally:
    l.release()
  if endpoint['joined'] is not None:
    return docker_err('endpoint already joined')
  ifname = install_if(network, endpoint)
  if ifname is None:
    return docker_err('failed to create interface')
  endpoint['joined'] = ifname
  l = db_lock.gen_wlock()
  while not l.acquire(): pass
  try:
    db['n'][req['NetworkID']]['e'][req['EndpointID']] = endpoint
  except:
    # rollback
    uninstall_if(ifname)
    return docker_err('failed to serialize')
  finally:
    db.sync()
    l.release()
  return {'InterfaceName': {'SrcName': ifname, 'DstPrefix': 'wg'},
          'StaticRoutes': [{'Destination': '0.0.0.0/0', 'RouteType': 1}],
          'DisableGatewayService': True}

@app.post('/NetworkDriver.Leave')
def leave():
  req = request.get_json(force=True)
  l = db_lock.gen_rlock()
  while not l.acquire(): pass
  try:
    endpoint = db['n'][req['NetworkID']]['e'][req['EndpointID']]
  except:
    return docker_err('failed to get endpoint')
  finally:
    l.release()
  if endpoint['joined'] is None:
    return docker_err('endpoint not joined')
  ifname = endpoint['joined']
  # the documentation is not clear at all on this, but when a network is unjoined libnetwork kindly
  # returns the interface to the initial namespace. it would be nice to delete it, but
  # unfortunately this only happens after Leave returns.
  #uninstall_if(ifname)  unfortunately, this doesn't work!
  endpoint['joined'] = None
  l = db_lock.gen_wlock()
  while not l.acquire(): pass
  try:
    db['n'][req['NetworkID']]['e'][req['EndpointID']] = endpoint
  except:
    # no rollback, since docker is still going to detach the interface
    return docker_err('failed to serialize')
  finally:
    db.sync()
    l.release()
  return {}

@app.post('/NetworkDriver.DiscoverNew')
@app.post('/NetworkDriver.DiscoverDelete')
def ignore():
  return {}

@app.errorhandler(404)
def not_found(error):
  return 'not implemented', 404

