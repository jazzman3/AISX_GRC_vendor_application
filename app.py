"""AISX GRC demo reference services. Not a regulatory compliance certification."""
import os, sqlite3, json, hmac, secrets, time, csv, io
from datetime import datetime, timezone
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

MODULES = {
 'inventory': {'name':'AI Asset Inventory & Governance Registry','short':'AI Inventory','icon':'◈','color':'#6c8dff','desc':'Register AI systems, vendors and usage, with accountable owners and risk classifications.',
   'fields':['name','owner','provider','usage','data_class','status'], 'sample':[
    ['Claims Review Assistant','Security Engineering','Internal','Document analysis','Confidential','Pilot'],
    ['Customer Service Agent','Customer Operations','External LLM','Customer support','Internal','Approved'],
    ['Hiring Screening Model','HR Technology','Vendor Model','Hiring decisions','Restricted','Review'] ],
   'metrics':['Registered AI assets','Under review','Restricted-data assets'], 'event':'Asset registered'},
 'risk': {'name':'AI Risk & Impact Assessment Platform','short':'AI Risk Assessments','icon':'◇','color':'#bd8aff','desc':'Score AI use cases against weighted security, privacy, fairness and oversight factors.',
   'fields':['system','owner','security','privacy','fairness','oversight'], 'sample':[
    ['Claims Review Assistant','Security Engineering',3,4,3,2],
    ['Customer Service Agent','Customer Operations',2,2,2,2],
    ['Hiring Screening Model','HR Technology',4,4,5,4]],
   'metrics':['Assessments','High-risk assessments','Average risk score'], 'event':'Assessment recorded'},
 'compliance': {'name':'AI Compliance & Audit Evidence Manager','short':'AI Compliance','icon':'▤','color':'#4dccb4','desc':'Track mapped controls, evidence references, owners and due dates; export audit-ready registers.',
   'fields':['control','framework','owner','evidence_uri','status','due_date'], 'sample':[
    ['AI governance accountability','NIST AI RMF','GRC Lead','evidence/policy.pdf','Complete','2026-12-15'],
    ['AI risk lifecycle review','ISO/IEC 42001','AI Risk Officer','evidence/review.md','In progress','2026-12-31'],
    ['Transparency review','EU AI Act','Legal Counsel','Not uploaded','Gap','2027-01-15']],
   'metrics':['Mapped controls','Evidence gaps','Complete controls'], 'event':'Control updated'},
 'vendor': {'name':'Third-Party AI Vendor Risk Manager','short':'Third-Party AI','icon':'⬡','color':'#f3b867','desc':'Maintain vendor due diligence findings, external-data exposure and mitigation owners.',
   'fields':['vendor','product','owner','data_shared','security_review','contract_status'], 'sample':[
    ['Northstar AI','Text Assistant API','IT Procurement','Confidential','Pending','Review'],
    ['Acme Models','Hosted Inference','AI Platform','Internal','Approved','Signed'],
    ['Sapphire Analytics','Decision Engine','Risk Office','Restricted','Pending','Review']],
   'metrics':['AI vendors','Pending security reviews','Restricted data sharing'], 'event':'Vendor registered'},
 'monitoring': {'name':'Continuous AI Risk Monitoring & Incident Manager','short':'AI Risk Monitoring','icon':'◉','color':'#f17f99','desc':'Ingest AI risk signals, log incidents and assign investigation status and mitigation owners.',
   'fields':['system','signal','severity','owner','status','source'], 'sample':[
    ['Claims Review Assistant','Prompt injection flagged','High','SecOps','Investigating','Gateway'],
    ['Customer Service Agent','Answer-quality score declined','Medium','ML Ops','Open','Evaluation'],
    ['Hiring Screening Model','Fairness review overdue','Critical','AI Risk Officer','Escalated','GRC Review']],
   'metrics':['Risk events','High/critical events','Open investigations'], 'event':'Risk signal recorded'}
}

class Record(BaseModel):
    values: dict[str, str | int | float] = Field(default_factory=dict)

class Update(BaseModel):
    values: dict[str, str | int | float] = Field(default_factory=dict)

security = HTTPBasic(auto_error=False)

def build_app(module='inventory', db_path=None):
    if module not in MODULES: raise ValueError(module)
    cfg=MODULES[module]
    path=db_path or os.getenv('DB_PATH',f'/data/{module}.db')
    def con():
        conn=sqlite3.connect(path,timeout=10)
        conn.row_factory=sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        return conn
    os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
    with con() as db:
        db.execute('CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, record_id INTEGER, ts TEXT NOT NULL)')
        if db.execute('SELECT COUNT(*) FROM records').fetchone()[0]==0 and os.getenv('SEED_DEMO','1')=='1':
            for vals in cfg['sample']:
                stamp=datetime.now(timezone.utc).isoformat()
                db.execute('INSERT INTO records(payload,created_at,updated_at) VALUES(?,?,?)',(json.dumps(dict(zip(cfg['fields'],vals))),stamp,stamp))
    app=FastAPI(title='AISX '+cfg['name'],version='1.0.0',docs_url='/docs' if os.getenv('ENABLE_DOCS','0')=='1' else None,redoc_url=None)
    def auth(c:HTTPBasicCredentials=Depends(security)):
        username=os.getenv('ADMIN_USER','aisx-admin')
        password=os.getenv('ADMIN_PASSWORD','')
        if not password or len(password)<12:
            raise HTTPException(503,'Configure ADMIN_PASSWORD with at least 12 characters')
        valid=c is not None and hmac.compare_digest(c.username.encode(),username.encode()) and hmac.compare_digest(c.password.encode(),password.encode())
        if not valid: raise HTTPException(401,'Authentication required',headers={'WWW-Authenticate':'Basic realm="AISX Demo"'})
        return c.username
    def audit(db,action,rid=None):
        db.execute('INSERT INTO audit(action,record_id,ts) VALUES(?,?,?)',(action,rid,datetime.now(timezone.utc).isoformat()))
    def validate(v):
        if not isinstance(v,dict) or any(f not in v for f in cfg['fields']): raise HTTPException(422,f"Required fields: {cfg['fields']}")
        if any(len(str(v[f]))>400 for f in cfg['fields']): raise HTTPException(422,'Field too long')
        if module=='risk':
            for field in cfg['fields'][2:]:
                try: score=int(v[field])
                except: raise HTTPException(422,'Risk factors must be integers 1–5')
                if score not in [1,2,3,4,5]: raise HTTPException(422,'Risk factors must be 1–5')
                v[field]=score
        else:
            for f in cfg['fields']:
                if not str(v[f]).strip(): raise HTTPException(422,'Fields cannot be blank')
        return {f:v[f] for f in cfg['fields']}
    def decorate(rec):
        if module=='risk':
            # demonstration scoring model, not calibrated model risk
            vals=[int(rec[f]) for f in cfg['fields'][2:]]
            rec['risk_score']=round(sum(vals)/len(vals)*20)
            rec['risk_band']='High' if rec['risk_score']>=70 else 'Medium' if rec['risk_score']>=45 else 'Low'
        if module=='vendor':
            rec['risk_band']='High' if rec['data_shared']=='Restricted' or rec['security_review']=='Pending' else 'Low'
        return rec
    def listing():
        with con() as db: rows=db.execute('SELECT * FROM records ORDER BY id DESC').fetchall()
        return [decorate({'id':r['id'],**json.loads(r['payload']),'created_at':r['created_at']}) for r in rows]
    @app.middleware('http')
    async def headers(req:Request,call_next):
        res=await call_next(req)
        for k,v in {'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'"}.items():res.headers[k]=v
        return res
    @app.get('/health')
    def health():
        with con() as db: db.execute('SELECT 1')
        return {'status':'ok','module':module}
    @app.get('/api/records')
    def records(user=Depends(auth)):return listing()
    @app.post('/api/records',status_code=201)
    def create(item:Record,user=Depends(auth)):
        v=validate(item.values);stamp=datetime.now(timezone.utc).isoformat()
        with con() as db:
            cur=db.execute('INSERT INTO records(payload,created_at,updated_at) VALUES(?,?,?)',(json.dumps(v),stamp,stamp));audit(db,cfg['event'],cur.lastrowid);rid=cur.lastrowid
        return {'id':rid,**decorate(v)}
    @app.patch('/api/records/{rid}')
    def update(rid:int,item:Update,user=Depends(auth)):
        with con() as db:
            row=db.execute('SELECT payload FROM records WHERE id=?',(rid,)).fetchone()
            if not row:raise HTTPException(404,'Record not found')
            v={**json.loads(row['payload']),**item.values};v=validate(v)
            db.execute('UPDATE records SET payload=?, updated_at=? WHERE id=?',(json.dumps(v),datetime.now(timezone.utc).isoformat(),rid));audit(db,'Record modified',rid)
        return {'id':rid,**decorate(v)}
    @app.get('/api/audit')
    def audit_list(user=Depends(auth)):
        with con() as db: return [dict(row) for row in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
    @app.get('/api/summary')
    def summary(user=Depends(auth)):
        rows=listing();n=len(rows)
        if module=='inventory': vals=[n,sum(x['status']=='Review' for x in rows),sum(x['data_class']=='Restricted' for x in rows)]
        elif module=='risk': vals=[n,sum(x['risk_band']=='High' for x in rows),round(sum(x['risk_score'] for x in rows)/n) if n else 0]
        elif module=='compliance':vals=[n,sum(x['status']=='Gap' for x in rows),sum(x['status']=='Complete' for x in rows)]
        elif module=='vendor':vals=[n,sum(x['security_review']=='Pending' for x in rows),sum(x['data_shared']=='Restricted' for x in rows)]
        else:vals=[n,sum(x['severity'] in ['High','Critical'] for x in rows),sum(x['status']!='Resolved' for x in rows)]
        return {'labels':cfg['metrics'],'values':vals,'module':module}
    @app.get('/api/export.csv')
    def export(user=Depends(auth)):
        out=io.StringIO();writer=csv.DictWriter(out,fieldnames=['id']+cfg['fields'],extrasaction='ignore');writer.writeheader();writer.writerows(listing())
        return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename="aisx-{module}.csv"'})
    @app.get('/',response_class=HTMLResponse)
    def dashboard(user=Depends(auth)):
        html=open(os.path.join(os.path.dirname(__file__),'dashboard.html'),encoding='utf-8').read()
        return html.replace('__TITLE__',cfg['name']).replace('__SHORT__',cfg['short']).replace('__DESC__',cfg['desc']).replace('__COLOR__',cfg['color']).replace('__MODULE__',module).replace('__FIELDS__',json.dumps(cfg['fields'])).replace('__LABELS__',json.dumps(cfg['metrics']))
    return app

app=build_app(os.getenv('MODULE','inventory'))
