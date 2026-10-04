"""Reproduce the locked host frontend build probe; no production app is built."""
from pathlib import Path
import json,os,shutil,subprocess
ROOT=Path(__file__).resolve().parents[1]
def main():
 dest=ROOT/'tmp/phase0';dest.mkdir(parents=True,exist_ok=True)
 for src,target in [('frontend-package.json','package.json'),('frontend-package-lock.json','package-lock.json'),('frontend-main.tsx','main.tsx'),('frontend-index.html','index.html')]:
  shutil.copyfile(ROOT/'tools/compatibility'/src,dest/target)
 env={**os.environ,'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD':'1'}
 subprocess.run(['npm','ci','--ignore-scripts','--no-audit','--no-fund'],cwd=dest,env=env,check=True,timeout=120)
 subprocess.run([str(dest/'node_modules/.bin/vite'),'build',str(dest),'--outDir','build-probe'],cwd=ROOT,check=True,timeout=60)
 report={'status':'passed','node':subprocess.check_output(['node','--version'],text=True).strip(),'packages':json.loads((dest/'package.json').read_text())['dependencies'],'limits':['Minimal TSX bundle only; no full application typecheck.','Container Node 24 production build remains Phase 1.']}
 (ROOT/'docs/evidence/frontend-probe.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
