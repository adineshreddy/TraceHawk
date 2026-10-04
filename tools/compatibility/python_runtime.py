"""Smoke-check ARM64 Python libraries and consume an actual Go-produced record."""
import json, platform, time
from importlib.metadata import version
from confluent_kafka import Consumer, Producer, libversion
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import create_engine, text
import psycopg
import alembic
from prometheus_client import CollectorRegistry, Counter
class Check(BaseModel):
    value: int
assert Check(value=1).value==1
app=FastAPI()
engine=create_engine('sqlite://')
with engine.connect() as conn: assert conn.execute(text('select 1')).scalar()==1
Counter('probe_events_total','Probe',registry=CollectorRegistry()).inc()
c=Consumer({'bootstrap.servers':'127.0.0.1:19092','group.id':'tracehawk-phase0','auto.offset.reset':'earliest','enable.auto.commit':False})
c.subscribe(['phase0-go'])
try:
 deadline=time.monotonic()+40
 while time.monotonic()<deadline:
  m=c.poll(1)
  if m is not None and not m.error():
   assert m.value()==b'tracehawk-go-arm64'
   break
 else:raise RuntimeError('Go record not received')
finally:c.close()
p=Producer({'bootstrap.servers':'127.0.0.1:19092','enable.idempotence':True})
results=[]
p.produce('phase0-python',key='probe',value='tracehawk-python-arm64',on_delivery=lambda e,m:results.append(e))
assert p.flush(15)==0 and results==[None],results
report={'broker_version':'4.3.0','broker_image':'apache/kafka:4.3.0@sha256:0be4c9eb3565733612d2836d65636fd611a219ebcf5b4162e5ac259ea0ecb907','status':'passed','python':platform.python_version(),'architecture':platform.machine(),
 'libraries':{x:version(x) for x in ['confluent-kafka','fastapi','pydantic','SQLAlchemy','alembic','psycopg','psycopg-binary','prometheus-client']},
 'librdkafka':libversion()[0],'go_to_python_delivery':True,'python_producer_acknowledged':True,
 'limits':['Client/broker and library smoke test only; no detector, database recovery or throughput claims.']}
open('/work/docs/evidence/runtime-probe.json','w').write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
