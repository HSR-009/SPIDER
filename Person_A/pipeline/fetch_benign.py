import argparse, hashlib, json, time, urllib.request, urllib.parse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RAW=ROOT/'data'/'raw'/'benign'; ARCH=RAW/'archives'; MAN=RAW/'manifest.jsonl'
TOP_URL='https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json'; CAP=15*1024*1024
UA='SPIDER-static-research/1.0'
def getj(url):
 r=urllib.request.Request(url,headers={'User-Agent':UA})
 with urllib.request.urlopen(r,timeout=30) as x:return json.load(x)
def norm(s):return s.lower().replace('_','-').replace('.','-')
def main():
 p=argparse.ArgumentParser();p.add_argument('--top',type=int,default=1500);p.add_argument('--versions',type=int,choices=[1,2],default=2);p.add_argument('--names-file');p.add_argument('--delay',type=float,default=.15);a=p.parse_args()
 bad=set(); mal=ROOT/'data'/'processed'/'malicious_for_b.jsonl'
 with mal.open(encoding='utf-8') as f:
  for l in f:
   if l.strip():bad.add(norm(json.loads(l)['package_name']))
 names=[x.strip() for x in Path(a.names_file).read_text(encoding='utf-8').splitlines() if x.strip()] if a.names_file else [x['project'] for x in getj(TOP_URL).get('rows',[]) if x.get('project')]
 names=[n for n in names[:a.top] if norm(n) not in bad];ARCH.mkdir(parents=True,exist_ok=True);MAN.parent.mkdir(parents=True,exist_ok=True);new=0;fail=0
 with MAN.open('a',encoding='utf-8') as mf:
  for i,name in enumerate(names,1):
   try:
    d=getj('https://pypi.org/pypi/'+urllib.parse.quote(name,safe='')+'/json'); info=d.get('info',{}); real=info.get('name',name)
    if norm(real) in bad:continue
    rel=[]
    for ver,files in d.get('releases',{}).items():
     fs=[z for z in files if z.get('packagetype')=='sdist' and z.get('url') and z.get('digests',{}).get('sha256') and 0<int(z.get('size') or 0)<=CAP and not z.get('yanked',False)]
     if fs:
      z=min(fs,key=lambda x:int(x['size']));rel.append((z.get('upload_time_iso_8601',''),ver,z))
    rel.sort(); chosen=([rel[-1]] if a.versions==1 else ([rel[(len(rel)-1)//2]] if len(rel)<2 or rel[(len(rel)-1)//2][1]==rel[-1][1] else [rel[(len(rel)-1)//2],rel[-1]])) if rel else []
    for _,ver,z in chosen:
     fn=z['filename'];dest=ARCH/(norm(real)+'__'+ver.replace('/','_')+'__'+fn)
     if dest.exists():continue
     req=urllib.request.Request(z['url'],headers={'User-Agent':UA});h=hashlib.sha256();size=0;tmp=dest.with_suffix(dest.suffix+'.part')
     try:
      with urllib.request.urlopen(req,timeout=60) as r,tmp.open('wb') as w:
       while True:
        b=r.read(1024*1024)
        if not b:break
        size+=len(b)
        if size>CAP:raise ValueError('over 15 MB')
        h.update(b);w.write(b)
      if size!=int(z['size']) or h.hexdigest()!=z['digests']['sha256']:raise ValueError('size/SHA256 mismatch')
      tmp.replace(dest)
     except Exception:tmp.unlink(missing_ok=True);raise
     row={'package_name':real,'version':ver,'filename':fn,'archive_path':dest.relative_to(ROOT).as_posix(),'url':z['url'],'upload_time':z.get('upload_time_iso_8601',''),'packagetype':'sdist','label':0,'sha256':h.hexdigest(),'size_bytes':size,'source':'popular PyPI projects; assumed benign, not verified'}
     mf.write(json.dumps(row)+'\n');mf.flush();new+=1;print('OK',real,ver,size)
    if i%50==0:print(f'Progress {i}/{len(names)}; new archives={new}; failures={fail}')
    time.sleep(max(0,a.delay))
   except Exception as e:fail+=1;print('SKIP/ERROR',name,repr(e))
 print(f'Done: {new} new archives, {fail} errors. Manifest: {MAN}. Archives were hash-checked, not extracted or run.')
if __name__=='__main__':main()
