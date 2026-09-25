"""Native WebSocket protocol test without additional packages or secret output."""
import argparse,base64,hashlib,http.cookiejar,json,secrets,socket,struct,urllib.parse,urllib.request
p=argparse.ArgumentParser();p.add_argument('--base',required=True);p.add_argument('--origin',required=True);a=p.parse_args()
url=urllib.parse.urlparse(a.base)
def session():
 jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
 with opener.open(urllib.request.Request(a.base+'/api/auth/demo',data=b'{}',headers={'Origin':a.origin,'Content-Type':'application/json'})) as r:assert r.status==200
 return opener,'; '.join(c.name+'='+c.value for c in jar)
class Socket:
 def __init__(self,cookie):
  self.sock=socket.create_connection((url.hostname,url.port),timeout=3);self.buffer=b''
  key=base64.b64encode(secrets.token_bytes(16)).decode()
  request=f'GET /api/ws HTTP/1.1\r\nHost: {url.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {a.origin}\r\nCookie: {cookie}\r\n\r\n'
  self.sock.sendall(request.encode());data=b''
  while b'\r\n\r\n' not in data:data+=self.sock.recv(4096)
  headers,self.buffer=data.split(b'\r\n\r\n',1)
  assert b'101 Switching Protocols' in headers
  accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
  assert accept in headers
  assert self.read()['type']=='connected'
 def take(self,n):
  while len(self.buffer)<n:self.buffer+=self.sock.recv(4096)
  value,self.buffer=self.buffer[:n],self.buffer[n:];return value
 def read(self):
  first,length=self.take(2);length&=127
  if length==126:length=struct.unpack('!H',self.take(2))[0]
  elif length==127:length=struct.unpack('!Q',self.take(8))[0]
  return json.loads(self.take(length))
 def send(self,value):
  data=json.dumps(value).encode();mask=secrets.token_bytes(4)
  assert len(data)<126
  self.sock.sendall(bytes([0x81,0x80|len(data)])+mask+bytes(v^mask[i%4] for i,v in enumerate(data)))
one,cookie1=session();two,cookie2=session();first=Socket(cookie1);second=Socket(cookie2)
first.send({'type':'ping'});assert first.read()['type']=='pong'
first.send({'type':'release'});assert first.read()['type']=='error'
with one.open(urllib.request.Request(a.base+'/api/assets',data=b'{"name":"WebSocket test"}',headers={'Origin':a.origin,'Content-Type':'application/json'})) as r:assert r.status==200
assert first.read()['type']=='asset.created'
second.sock.settimeout(0.5)
try:
 second.read();raise AssertionError('Cross-tenant event received')
except socket.timeout:pass
first.sock.close();second.sock.close()
print(json.dumps({'bidirectional_ping':'passed','mutation_message_rejected':'passed','same_tenant_event':'passed','cross_tenant_event_isolation':'passed'}))
