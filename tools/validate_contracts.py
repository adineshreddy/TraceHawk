"""Validate schemas, parity cases, semantic invariants and actual normalized logs."""
from pathlib import Path
from decimal import Decimal
import copy
import hashlib
import ipaddress
import json
from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[1]


def semantics(name,data):
    if name=='event':
        assert data['published_at_us']>=data['ingested_at_us'], 'publish before ingestion'
        start=data['original_timestamp_us']
        if data['event_kind']=='connection':
            duration=data['connection']['duration_us']
            expected='original_start_fallback' if duration is None else 'connection_activity_end'
            assert data['time_basis']==expected, 'duration/time-basis mismatch'
            assert data['event_time_us']==start+(duration or 0), 'incorrect connection time'
        else:
            assert data['event_time_us']==start, 'incorrect DNS time'
            dns=data['dns']
            if dns['query'] is not None:assert dns['query']==dns['query'].lower().rstrip('.'), 'unnormalized DNS name'
            if dns['rcode']==3:assert dns['rcode_name']=='NXDOMAIN', 'inconsistent NXDOMAIN'
    elif name=='alert':
        assert data['first_event_time_us']<=data['last_event_time_us']
        assert data['window_start_us']<data['window_end_us']
        assert data['updated_at_us']>=data['created_at_us']
        assert data['suppressed']==(data['suppression_id'] is not None)
        assert data['evidence_total_count']>=len(data['evidence_event_ids'])
        assert data['evidence_truncated']==(data['evidence_total_count']>len(data['evidence_event_ids']))
    elif name=='suppression':assert data['expires_at_us']>data['created_at_us']
    elif name=='scenario':assert data['time_end_us']>=data['time_start_us']
    elif name=='indicators':
        for entry in data['entries']:
            if entry['kind']=='ip':ipaddress.ip_address(entry['value'])
            else:assert entry['value']==entry['value'].lower().rstrip('.') and ' ' not in entry['value']


def main():
    validators={}
    for p in sorted((ROOT/'contracts/schemas').glob('*.json')):
        schema=json.loads(p.read_text());Draft202012Validator.check_schema(schema)
        validators[p.stem]=Draft202012Validator(schema,format_checker=FormatChecker())
    cases=json.loads((ROOT/'contracts/validation-cases.json').read_text())
    for c in cases:
        valid=not list(validators[c['schema']].iter_errors(c['data']))
        assert valid==c['valid'], c['name']
        if valid:semantics(c['schema'],c['data'])
    rows=[json.loads(s) for s in (ROOT/'scenarios/phase0/normalized-events.jsonl').read_text().splitlines()]
    ids=set()
    for row in rows:
        validators['event'].validate(row);semantics('event',row)
        assert row['event_id'] not in ids;ids.add(row['event_id'])
        p=row['provenance']
        identity=[row['scope_id'],row['sensor_id'],p['source_generation_id'],p['log_kind'],p['record_offset']]
        assert row['event_id']==hashlib.sha256(json.dumps(identity,separators=(',',':')).encode()).hexdigest()
    # Cross-field invariants are application checks, beyond JSON Schema parity.
    negative=[]
    for kind,field,value in [('event','event_time_us',1),('event','published_at_us',0),('alert','last_event_time_us',0),('alert','suppressed',True),('suppression','expires_at_us',0)]:
        example='connection' if kind=='event' else kind
        v=json.loads((ROOT/f'contracts/examples/{example}.json').read_text());v[field]=value
        try:semantics(kind,v)
        except AssertionError:negative.append(f'{kind}:{field}')
        else:raise AssertionError(f'Semantic negative accepted: {kind}:{field}')
    from openapi_spec_validator import validate
    api=json.loads((ROOT/'contracts/openapi.json').read_text())
    validate(api)
    for name in ('alert','event','rules','suppression','indicators'):
        canonical=json.loads((ROOT/f'contracts/schemas/{name}.json').read_text())
        canonical.pop('$schema');canonical.pop('$id')
        assert api['components']['schemas'][name.title()]==canonical, f'OpenAPI schema drift: {name}'
    (ROOT/'docs/evidence/openapi.json').write_text(json.dumps({'status':'passed','openapi':'3.1.0','paths':len(api['paths']),'embedded_schema_parity':True,'validator':'openapi-spec-validator 0.9.0','note':'OpenAPI structure and canonical schemas; actual Phase 1 response parity is checked by tools/verify_phase1.py.'},indent=2)+'\n')
    manifest=json.loads((ROOT/'scenarios/phase0/manifest.json').read_text())
    validators['scenario'].validate(manifest)
    assert manifest['capture_sha256']==hashlib.sha256((ROOT/'scenarios/phase0'/manifest['capture_file']).read_bytes()).hexdigest()
    report={'status':'passed','schemas':len(validators),'schema_cases':len(cases),
            'semantic_negative_cases':negative,'actual_zeek_normalized_records':len(rows),
            'limitations':['Go parity covers JSON Schema including formats; service-level semantic enforcement is required in Phase 1.']}
    (ROOT/'docs/evidence/contracts-python.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
