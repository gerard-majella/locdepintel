import argparse, json, os, pathlib, sys, time, subprocess, shutil, threading, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from . import core

LOCK=threading.Lock()
JOB_LOCK=threading.Lock()
JOB={'state':'idle','stage':'Not started','started':None,'ended':None,'result':None,'error':None}
def background_scan():
    """Run one discover + exact-version advisory cycle, reporting real stages."""
    def worker():
        try:
            with JOB_LOCK: JOB.update(state='running',stage='Discovering environments',started=core.timestamp())
            discovered=core.scan()
            with JOB_LOCK: JOB['stage']='Checking exact versions against OSV'
            checked=core.assess()
            with JOB_LOCK:
                JOB.update(state='complete' if checked.get('state') in ('ok','no-packages') and not discovered.get('warnings') else 'partial',
                    stage='Scan finished',ended=core.timestamp(),result={'discovery':discovered,'security':checked})
        except Exception as exc:
            with JOB_LOCK: JOB.update(state='error',stage='Scan failed',ended=core.timestamp(),error=str(exc)[:500])
        finally: LOCK.release()
    if not LOCK.acquire(blocking=False): return False
    with JOB_LOCK: JOB.update(state='starting',stage='Starting',started=core.timestamp(),ended=None,result=None,error=None)
    threading.Thread(target=worker,daemon=True,name='locdepintel-fullscan').start()
    return True

STATIC=pathlib.Path(__file__).parent/'static'
class Handler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*args): pass
    def send(self,code,body,typ='application/json'):
        b=(json.dumps(body).encode() if typ=='application/json' else body)
        self.send_response(code); self.send_header('Content-Type',typ+'; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.headers.get('Host') not in ('127.0.0.1:8765','localhost:8765'):return self.send(403,{'error':'Invalid host'})
        p=urlparse(self.path).path
        if p=='/api/state': return self.send(200,core.state())
        if p=='/api/overview': return self.send(200,core.overview())
        if p=='/api/onboarding': return self.send(200,core.setup_status())
        if p=='/api/scan-status':
            with JOB_LOCK: return self.send(200,dict(JOB))
        if p=='/api/inventory': return self.send(200,core.inventory())
        if p=='/api/grouped-findings': return self.send(200,core.grouped_findings())
        if p=='/api/pulse': return self.send(200,core.pulse())
        if p=='/api/export':
            data=json.dumps(core.export(),indent=2).encode();return self.send(200,data,'application/json')
        if p=='/': p='/index.html'
        if p not in ['/index.html','/app.js','/style.css']: return self.send(404,{'error':'Not found'})
        f=STATIC/p[1:]; typ='text/html' if p.endswith('.html') else 'text/javascript' if p.endswith('.js') else 'text/css'
        return self.send(200,f.read_bytes(),typ)
    def do_POST(self):
        if self.headers.get('Host') not in ('127.0.0.1:8765','localhost:8765'):return self.send(403,{'error':'Invalid host'})
        # API bound to loopback; require same-site Origin when browser supplies it. No CORS support.
        origin=self.headers.get('Origin','')
        if origin and origin not in ('http://127.0.0.1:8765','http://localhost:8765'): return self.send(403,{'error':'Invalid origin'})
        if self.headers.get('Content-Length','0') not in ('0',''):
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n>20000:return self.send(413,{'error':'Payload too large'})
                obj=json.loads(self.rfile.read(n))
            except Exception:return self.send(400,{'error':'Invalid JSON'})
        else:obj={}
        if self.path=='/api/onboarding':
            roots=obj.get('roots',None)
            skip=obj.get('skip',False)
            if not isinstance(skip,bool) or (roots is not None and (not isinstance(roots,list) or len(roots)>15 or any(not isinstance(x,str) or not x or len(x)>1000 for x in roots))):
                return self.send(400,{'error':'Invalid onboarding choices'})
            if not skip and not roots:return self.send(400,{'error':'Select at least one scan location'})
            return self.send(200,core.finish_onboarding(roots=roots,skip=skip))
        if self.path=='/api/scan-full':
            if not background_scan():return self.send(409,{'error':'Another scan is already running'})
            return self.send(202,{'state':'starting'})
        if self.path=='/api/pulse-sync':
            if not LOCK.acquire(blocking=False):return self.send(409,{'error':'Another task is running'})
            try:return self.send(200,core.sync_pulse())
            finally:LOCK.release()
        if self.path=='/api/package-intel':
            ecosystem=obj.get('ecosystem'); name=obj.get('name'); env=obj.get('env');version=obj.get('version')
            if not all(isinstance(x,str) for x in (ecosystem,name,env,version)) or any(len(x)>2048 for x in (ecosystem,name,env,version)):
                return self.send(400,{'error':'Invalid package selection'})
            with core.db() as con:
                known=con.execute('SELECT 1 FROM inventory WHERE active=1 AND ecosystem=? AND name=? AND env=? AND version=?',(ecosystem,name,env,version)).fetchone()
            if not known:return self.send(404,{'error':'Package not in discovered inventory'})
            try:return self.send(200,core.package_intelligence(ecosystem,name))
            except Exception as ex:return self.send(502,{'error':'Live registry metadata unavailable: '+str(ex)[:180]})
        if self.path=='/api/terminal':
            requested=obj.get('path')
            if sys.platform!='darwin':return self.send(501,{'error':'Opening Terminal is available on macOS only. Copy the path on other systems.'})
            if not isinstance(requested,str) or len(requested)>2048:return self.send(400,{'error':'Invalid location'})
            with core.db() as con:
                known=con.execute('SELECT 1 FROM envs WHERE path=?',(requested,)).fetchone()
            if not known:return self.send(404,{'error':'Environment was not discovered'})
            path=pathlib.Path(requested)
            if not path.is_dir():return self.send(404,{'error':'Environment directory unavailable'})
            # AppleScript is static and takes only a validated path argument. Only changes the shell directory.
            script='on run argv\n tell application "Terminal" to do script "cd " & quoted form of (item 1 of argv)\n activate application "Terminal"\nend run'
            try:
                subprocess.Popen(['/usr/bin/osascript','-e',script,str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                return self.send(200,{'ok':True})
            except OSError as ex:return self.send(500,{'error':'Unable to open Terminal: '+str(ex)})
        if self.path=='/api/reveal':
            requested=obj.get('path')
            if not isinstance(requested,str) or len(requested)>2048:
                return self.send(400,{'error':'Invalid location'})
            # Only known inventory/environment paths may be revealed. No arbitrary command execution.
            with core.db() as con:
                known=con.execute('SELECT 1 FROM envs WHERE path=?',(requested,)).fetchone()
            if not known:return self.send(404,{'error':'Location was not discovered by LocDepIntel'})
            target=pathlib.Path(requested)
            if not target.exists():return self.send(404,{'error':'Location no longer exists'})
            try:
                if sys.platform=='darwin': cmd=['/usr/bin/open','-R',str(target)]
                elif sys.platform=='win32': cmd=['explorer.exe',str(target)]
                else:
                    explorer=shutil.which('xdg-open')
                    if not explorer:return self.send(501,{'error':'File manager integration unavailable; copy the location instead'})
                    cmd=[explorer,str(target if target.is_dir() else target.parent)]
                subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                return self.send(200,{'ok':True})
            except OSError as ex: return self.send(500,{'error':'Could not open location: '+str(ex)})
        if self.path=='/api/scan':
            if not LOCK.acquire(blocking=False):return self.send(409,{'error':'Another task is running'})
            try:return self.send(200,core.scan())
            finally:LOCK.release()
        if self.path=='/api/check':
            if not LOCK.acquire(blocking=False):return self.send(409,{'error':'Another task is running'})
            try:return self.send(200,core.assess())
            finally:LOCK.release()
        if self.path=='/api/roots':
            roots=obj.get('roots')
            if not isinstance(roots,list) or len(roots)>30 or any(not isinstance(x,str) or not x or len(x)>1000 for x in roots):return self.send(400,{'error':'Invalid roots'})
            # user chooses paths; no arbitrary scripts or shell commands are accepted
            c=core.load_config();c['roots']=[str(pathlib.Path(x).expanduser().resolve()) for x in roots];core.save_config(c)
            return self.send(200,{'ok':True,'roots':c['roots']})
        return self.send(404,{'error':'Not found'})

def notify_macos(message):
    if sys.platform!='darwin':return
    # only internally generated fixed strings, not attacker-controlled advisory names
    try:subprocess.run(['/usr/bin/osascript','-e',f'display notification "{message}" with title "LocDepIntel"'],timeout=5,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except Exception:pass

def run_scan(online=True,include_pulse=False):
    scanned=core.scan()
    with core.db() as con: before=con.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
    assessed=core.assess() if online else {'state':'skipped'}
    with core.db() as con: new_malware=con.execute('SELECT count(*) FROM events WHERE id>? AND kind=?',(before,'malware-alert')).fetchone()[0]
    if assessed.get('state')=='ok' and new_malware:
        notify_macos('A new malicious-package advisory affects an installed dependency. Open LocDepIntel.')
    pulse_result=core.sync_pulse() if online and include_pulse else {'state':'skipped'}
    return {'discovery':scanned,'security':assessed,'pulse':pulse_result}

def install_launchd(interval=21600):
    if sys.platform!='darwin':raise RuntimeError('launchd setup is supported only on macOS')
    if not 3600<=interval<=604800: raise ValueError('Interval must be 1 hour to 7 days')
    import plistlib
    directory=pathlib.Path.home()/'Library'/'LaunchAgents';directory.mkdir(parents=True,exist_ok=True)
    path=directory/'io.github.gerard-majella.locdepintel.plist'
    args=[str(pathlib.Path(sys.executable).resolve()),'-m','locdepintel','run-once']
    spec={'Label':'io.github.gerard-majella.locdepintel','ProgramArguments':args,'StartInterval':interval,'RunAtLoad':False,'StandardOutPath':str(core.home_data()/'monitor.log'),'StandardErrorPath':str(core.home_data()/'monitor-errors.log'),'WorkingDirectory':str(pathlib.Path(__file__).resolve().parent.parent)}
    path.write_bytes(plistlib.dumps(spec));os.chmod(path,0o600)
    # use current user launchd domain; if already registered, bootout then bootstrap
    uid=os.getuid();subprocess.run(['launchctl','bootout',f'gui/{uid}',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    p=subprocess.run(['launchctl','bootstrap',f'gui/{uid}',str(path)],capture_output=True,text=True)
    if p.returncode:raise RuntimeError(f'Could not register launchd job: {p.stderr.strip()}')
    return str(path)

def main():
    parser=argparse.ArgumentParser(prog='locdepintel',description='Local-first dependency watchdog (read-only)')
    sp=parser.add_subparsers(dest='command')
    serve=sp.add_parser('serve',help='Start local web UI');serve.add_argument('--port',type=int,default=8765)
    s=sp.add_parser('scan',help='Discover packages in configured roots');s.add_argument('--offline',action='store_true',help='Do not query OSV')
    sp.add_parser('run-once',help='Scan + advisory and Threat Pulse refresh for scheduler')
    sp.add_parser('pulse-sync',help='Fetch latest public GitHub security and malware advisories')
    sp.add_parser('status');sp.add_parser('inventory');sp.add_parser('alerts');sp.add_parser('export')
    conf=sp.add_parser('roots');conf.add_argument('paths',nargs='*',help='Replace discovery paths (none means list)')
    sched=sp.add_parser('schedule',help='Install user launchd job (macOS)');sched.add_argument('--hours',type=int,default=6)
    sp.add_parser('unschedule',help='Remove user launchd job')
    args=parser.parse_args()
    if args.command=='serve':
        if args.port!=8765:parser.error('UI is currently restricted to port 8765 for origin protection')
        srv=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
        print(f'LocDepIntel local UI: http://127.0.0.1:{args.port} (Ctrl+C to stop)')
        try:srv.serve_forever()
        except KeyboardInterrupt:pass
        finally:srv.server_close()
    elif args.command in ('scan','run-once'):
        print(json.dumps(run_scan(not getattr(args,'offline',False),args.command=='run-once'),indent=2))
    elif args.command=='pulse-sync':print(json.dumps(core.sync_pulse(),indent=2))
    elif args.command=='status': print(json.dumps(core.state()['stats'],indent=2)); print('Config:',core.config_path());print('Database:',core.db_path())
    elif args.command=='inventory':
        for p in core.inventory():print(f'{p["ecosystem"]:5} {p["name"]:36.36} {p["version"]:16.16}  {p["env"]}')
    elif args.command=='alerts':
        for x in core.state()['findings']:print(f'{x["kind"].upper()} | {x["name"]}@{x["version"]} | {x["advisory"]} | {x["env"]}')
    elif args.command=='export':print(json.dumps(core.export(),indent=2))
    elif args.command=='roots':
        if args.paths:
            c=core.load_config();c['roots']=[str(pathlib.Path(p).expanduser().resolve()) for p in args.paths];core.save_config(c)
        print('\n'.join(core.load_config()['roots']))
    elif args.command=='schedule': print('Scheduled with launchd:',install_launchd(args.hours*3600))
    elif args.command=='unschedule':
        if sys.platform!='darwin':parser.error('macOS only')
        path=pathlib.Path.home()/'Library'/'LaunchAgents'/'io.github.gerard-majella.locdepintel.plist'
        if path.exists():
            subprocess.run(['launchctl','bootout',f'gui/{os.getuid()}',str(path)],capture_output=True);path.unlink()
        print('Schedule removed.')
    else:parser.print_help()
if __name__=='__main__': main()
