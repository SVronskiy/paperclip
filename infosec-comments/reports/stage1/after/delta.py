"""Delta between the baseline rescan (master) and the rescan of pilot/hardening, by rule.
Usage: python3 -I delta.py <rescan dir (baseline)> <rescan2 dir (hardening)>"""
import glob, json, os, re, sys, collections
def load(root):
    out=[]
    sg=os.path.join(root,'semgrep-br.json')
    if os.path.exists(sg):
        for r in json.load(open(sg)).get('results',[]):
            out.append(('Semgrep', r['check_id'].split('.')[-1], r['path'].removeprefix('/src/')))
    for fn in glob.glob(os.path.join(root,'hs','*.json')):
        prefix=os.path.basename(fn)[:-5].replace('_','/')+'/'
        for x in json.load(open(fn)).get('analysisVulnerabilities') or []:
            v=x['vulnerabilities']
            rule=re.sub(r'^\(\d+/\d+\) \* Possible vulnerability detected: ','',v['details'].split('\n')[0],flags=re.I).strip()
            if v.get('language')=='Leaks': continue
            f=prefix+v['file']
            if re.search(r'(^|/)(__tests__|tests?|e2e|fixtures?)(/|$)|\.(test|spec|stories)\.',f): continue
            out.append(('Horusec', rule, f))
    return out
a=collections.Counter((t,r) for t,r,_ in load(sys.argv[1]))
b=collections.Counter((t,r) for t,r,_ in load(sys.argv[2]))
print(f"{'tool':8} {'rule':70} {'before':>6} {'after':>6}")
for k in sorted(set(a)|set(b), key=lambda k:(-(a[k]-b[k]),k)):
    if a[k]!=b[k] or a[k]>=5: print(f"{k[0]:8} {k[1][:70]:70} {a[k]:6} {b[k]:6}")
print('TOTAL', sum(a.values()), sum(b.values()))
