"""Live boundary tests. Starts no services and never prints credentials or cookies."""
import argparse, base64, http.cookiejar, json, secrets, urllib.request, urllib.error

parser=argparse.ArgumentParser()
parser.add_argument('--base', required=True)
parser.add_argument('--origin', required=True)
parser.add_argument('--live-ai', action='store_true')
args=parser.parse_args()
checks=[]
class Client:
    def __init__(self):
        self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(self,path,method='GET',body=None,origin=None):
        data=json.dumps(body).encode() if body is not None else None
        request=urllib.request.Request(args.base+path,data=data,method=method,headers={'Origin':origin or args.origin,'Content-Type':'application/json'})
        try:
            with self.client.open(request,timeout=180) as response:
                payload=response.read();return response.status,json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            raw=error.read()
            try:payload=json.loads(raw)
            except (ValueError,UnicodeError):payload={'error':'non-JSON error'}
            return error.code,payload

def check(name,condition):
    checks.append({'test':name,'passed':bool(condition)})
    if not condition: raise AssertionError(name)

account=Client()
email='boundary-'+secrets.token_hex(8)+'@example.test'
password=secrets.token_urlsafe(24)
s,new_user=account.call('/api/auth/register','POST',{'name':'Boundary Test','email':email,'password':password,'account_type':'personal'})
check('new account registration',s==200 and new_user['user']['account_type']=='personal' and not new_user['user']['demo'])
check('new account has no synthetic holdings',account.call('/api/assets')[1]['assets']==[])
check('registered account logout',account.call('/api/auth/logout','POST',{})[0]==204)
check('wrong password rejected',account.call('/api/auth/login','POST',{'email':email,'password':'wrong-password'})[0]==401)
check('password sign in',account.call('/api/auth/login','POST',{'email':email,'password':password})[0]==200)
check('duplicate registration rejected',account.call('/api/auth/register','POST',{'name':'Boundary Test','email':email,'password':password,'account_type':'personal'})[0]==409)

first,second=Client(),Client()
check('unauthenticated inventory rejected', first.call('/api/assets')[0]==401)
s,u1=first.call('/api/auth/demo','POST',{});check('demo login',s==200)
s,u2=second.call('/api/auth/demo','POST',{});check('isolated demo tenants',s==200 and u1['user']['tenant_id']!=u2['user']['tenant_id'])
s,dashboard=first.call('/api/dashboard');check('dashboard synthetic metadata',s==200 and dashboard['demo'] and dashboard['asset_count']==3)
check('cross-origin write rejected',first.call('/api/assets','POST',{'name':'blocked'},'https://attacker.invalid')[0]==403)
check('plaintext secret rejected',first.call('/api/assets','POST',{'name':'Secret','password':'not-a-real-secret'})[0]==400)
check('client tenant override rejected',first.call('/api/assets','POST',{'name':'x','tenant_id':'victim'})[0]==400)
s,asset=first.call('/api/assets','POST',{'name':'Boundary test','category':'documents','value':20,'currency':'CHF'});check('asset create',s==200)
check('cross-tenant patch rejected',second.call('/api/assets/'+asset['id'],'PATCH',{'name':'stolen'})[0]==404)
check('cross-tenant delete rejected',second.call('/api/assets/'+asset['id'],'DELETE')[0]==404)
check('asset update',first.call('/api/assets/'+asset['id'],'PATCH',{'name':'Updated'})[0]==200)
plan={'title':'Review plan','beneficiary':'Example beneficiary','guardian_emails':['guardian@example.test'],'required_approvals':1,'waiting_days':30}
s,p=first.call('/api/succession','POST',plan);check('succession draft',s==200 and p['status']=='draft')
s,p=first.call('/api/succession/'+p['id']+'/review','POST',{});check('review remains human-gated',s==200 and p['status']=='review_requested')
check('cannot repeat approval transition',first.call('/api/succession/'+p['id']+'/review','POST',{})[0]==409)
check('release endpoint absent',first.call('/api/succession/'+p['id']+'/release','POST',{})[0]==404)
envelope={'version':1,'algorithm':'AES-256-GCM','iv':base64.b64encode(secrets.token_bytes(12)).decode(),'ciphertext':base64.b64encode(secrets.token_bytes(48)).decode()}
s,item=first.call('/api/vault','POST',{'envelope':envelope});check('opaque envelope stored',s==200 and item['envelope']==envelope)
check('vault tenant isolation',second.call('/api/vault')[1]['items']==[])
check('vault foreign delete rejected',second.call('/api/vault/'+item['id'],'DELETE')[0]==404)
check('vault plaintext envelope field rejected',first.call('/api/vault','POST',{'envelope':dict(envelope,secret='no')})[0]==422)
check('vault delete',first.call('/api/vault/'+item['id'],'DELETE')[0]==200)
check('model selector authenticated',first.call('/api/models')[0]==200)
if args.live_ai:
    s,reply=first.call('/api/chat','POST',{'message':'Explain three safe next steps for the synthetic legacy inventory. Do not release anything.','model':'gpt-6-astra','locale':'en','history':[]})
    check('live gRPC provider generative UI',s==200 and bool(reply.get('cards')) and reply.get('verification',{}).get('source')=='live_provider')
    check('live provider action gate',reply['verification']['actions_executed'] is False)
check('logout',first.call('/api/auth/logout','POST',{})[0]==204)
check('revoked session rejected',first.call('/api/assets')[0]==401)
print(json.dumps({'checks':checks,'passed':len(checks),'failed':0},indent=2))
