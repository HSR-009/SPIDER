import ast, hashlib, json, tarfile, zipfile
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; MAN=ROOT/'data'/'raw'/'benign'/'manifest.jsonl'; OUT=ROOT/'data'/'processed'/'benign_for_b.jsonl'; MEMBER_CAP=2*1024*1024; TOTAL_CAP=30*1024*1024
SEV={'Command Execution':'HIGH','Dynamic Code Execution':'HIGH','Credential / Data Access':'HIGH','Network Activity':'MEDIUM','Obfuscation':'MEDIUM','Install-Time / Package Execution':'HIGH'}
def analyze(src,path):
 try:t=ast.parse(src,filename=path)
 except (SyntaxError,ValueError) as e:return [{'category':'Parse Error','indicator':'SyntaxError','severity':'MEDIUM','file':path,'line':getattr(e,'lineno',None),'evidence':f"Unable to parse Python source: {getattr(e,'msg',str(e))}"}]
 aliases={}
 for n in ast.walk(t):
  if isinstance(n,ast.Import):
   for a in n.names:aliases[a.asname or a.name.split('.')[0]]=a.name if a.asname else a.name.split('.')[0]
  elif isinstance(n,ast.ImportFrom):
   for a in n.names:aliases[a.asname or a.name]=f'{n.module}.{a.name}'
 out=[]
 def add(cat,ind,n,ev):out.append({'category':cat,'indicator':ind,'severity':SEV[cat],'file':path,'line':getattr(n,'lineno',None),'evidence':ev})
 for n in ast.walk(t):
  if isinstance(n,ast.Call):
   f=n.func
   if isinstance(f,ast.Attribute) and isinstance(f.value,ast.Name):
    r=aliases.get(f.value.id)
    if r=='os' and f.attr=='system':add('Command Execution','os.system',n,'os.system() call detected')
    if r=='subprocess' and f.attr in ('run','Popen'):add('Command Execution','subprocess.'+f.attr,n,f'subprocess.{f.attr}() call detected')
    if r=='socket' and f.attr=='socket':add('Network Activity','socket',n,'socket() call detected')
    if r=='requests' and f.attr in ('get','post','request'):add('Network Activity','requests.'+f.attr,n,'Network request detected')
    if f.attr=='urlopen' and isinstance(f.value,ast.Attribute) and isinstance(f.value.value,ast.Name) and aliases.get(f.value.value.id)=='urllib' and f.value.attr=='request':add('Network Activity','urllib.request.urlopen',n,'Network request detected')
    if r=='base64':add('Obfuscation','base64.'+f.attr,n,'base64 operation detected')
   if isinstance(f,ast.Name):
    if f.id in ('eval','exec','compile'):add('Dynamic Code Execution',f.id,n,f'{f.id}() call detected')
    if aliases.get(f.id,'').startswith('base64.'):add('Obfuscation',aliases[f.id],n,'Imported base64 operation detected')
    if f.id=='setup' or aliases.get(f.id)=='setuptools.setup':add('Install-Time / Package Execution','setuptools.setup',n,'setuptools.setup() detected')
  if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and aliases.get(n.value.id)=='os' and n.attr=='environ':add('Credential / Data Access','os.environ',n,'os.environ access detected')
  if isinstance(n,ast.Constant) and isinstance(n.value,str):
   for s in ('.ssh/','.aws/credentials','.netrc','.env'):
    if s in n.value:add('Credential / Data Access',s,n,f'Sensitive path {s} detected')
  if isinstance(n,ast.ImportFrom) and n.module=='setuptools.command.install':add('Install-Time / Package Execution','setuptools.command.install',n,'Custom setuptools install command detected')
 return out
def members(path):
 total=0
 if zipfile.is_zipfile(path):
  with zipfile.ZipFile(path) as z:
   for m in z.infolist():
    if m.is_dir() or not m.filename.lower().endswith('.py') or m.file_size>MEMBER_CAP:continue
    total+=m.file_size
    if total>TOTAL_CAP:break
    try:yield m.filename,z.read(m).decode('utf-8','replace')
    except Exception:pass
 else:
  try:
   with tarfile.open(path,'r:*') as z:
    for m in z.getmembers():
     if not m.isfile() or not m.name.lower().endswith('.py') or m.size>MEMBER_CAP:continue
     total+=m.size
     if total>TOTAL_CAP:break
     f=z.extractfile(m)
     if f:
      try:yield m.name,f.read(MEMBER_CAP+1).decode('utf-8','replace')
      except Exception:pass
  except (tarfile.TarError,OSError):return
def main():
 if not MAN.exists():raise SystemExit(f'Missing {MAN}; run fetch_benign.py first.')
 records={}
 for l in MAN.read_text(encoding='utf-8').splitlines():
  if l.strip():
   r=json.loads(l);records[(r['package_name'],r['version'])]=r
 OUT.parent.mkdir(parents=True,exist_ok=True);written=0
 with OUT.open('w',encoding='utf-8',newline='\n') as o:
  for (name,ver),m in sorted(records.items()):
   p=ROOT/m['archive_path']
   if not p.is_file():print('MISSING',p);continue
   h=hashlib.sha256(p.read_bytes()).hexdigest()
   if h!=m['sha256']:print('HASH MISMATCH',name,ver);continue
   findings=[];npy=0;perr=0
   for fn,src in members(p):
    npy+=1;f=analyze(src,fn);perr+=sum(x['category']=='Parse Error' for x in f);findings.extend(f)
   valid=[x for x in findings if x['category']!='Parse Error'];sev=[x['severity'] for x in valid]
   row={'package_id':f'{name}=={ver}','package_name':name,'version':ver,'label':0,'source':'popular PyPI projects; assumed benign, not verified','in_index':None,'index_annotated':None,'n_py_files':npy,'n_findings':len(valid),'category_counts':dict(Counter(x['category'] for x in valid)),'max_severity':'HIGH' if 'HIGH' in sev else ('MEDIUM' if 'MEDIUM' in sev else ('LOW' if 'LOW' in sev else None)),'parse_error_count':perr,'failed_static_analysis':int(perr>0),'findings':findings}
   o.write(json.dumps(row,sort_keys=True)+'\n');written+=1
 print(f'Wrote {written} rows to {OUT}. Archives were read in memory, never extracted or executed.')
 print('Note: rules mirror analyzer v1; keep analyzer.py frozen and compare rule parity before interpreting results.')
if __name__=='__main__':main()
