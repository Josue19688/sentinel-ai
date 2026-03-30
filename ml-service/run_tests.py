import sys, os
sys.path.insert(0, '.')
from tests.test_normalizer_multisiem import SAMPLES, REQUIRED_FIELDS
from app.gateway.normalizer import auto_normalize
import json

results = []
passed = failed = 0
for i, sample in enumerate(SAMPLES, 1):
    errors = []
    try:
        r = auto_normalize(sample['payload'])
        if 'expect_source' in sample and r.get('source') != sample['expect_source']:
            errors.append(f"source={r['source']} != {sample['expect_source']}")
        if 'expect_source_prefix' in sample and not str(r.get('source','')).startswith(sample['expect_source_prefix']):
            errors.append(f"source prefix mismatch: {r['source']}")
        if 'expect_pattern' in sample and r.get('pattern_hint') != sample['expect_pattern']:
            errors.append(f"pattern={r['pattern_hint']} != {sample['expect_pattern']}")
        if 'expect_sev_min' in sample and r.get('severity_score',0) < sample['expect_sev_min']:
            errors.append(f"score={r['severity_score']} < {sample['expect_sev_min']}")
        missing = REQUIRED_FIELDS - set(r.keys())
        if missing:
            errors.append(f"campos faltantes: {missing}")
    except Exception as e:
        errors.append(str(e))
        r = {}

    status = 'PASS' if not errors else 'FAIL'
    if not errors: passed += 1
    else: failed += 1

    results.append({'n': i, 'name': sample['name'], 'status': status,
                    'source': r.get('source','N/A'), 'pattern': r.get('pattern_hint','N/A'),
                    'severity': r.get('severity','N/A'), 'score': r.get('severity_score',0),
                    'asset_id': r.get('asset_id','N/A'),
                    'ext_id': str(r.get('external_event_id',''))[:24],
                    'errors': errors})

for r in results:
    mark = '[PASS]' if r['status'] == 'PASS' else '[FAIL]'
    print(f"  [{r['n']:02d}] {mark}  {r['name']}")
    if r['status'] == 'PASS':
        print(f"       source={r['source']}  pattern={r['pattern']}  sev={r['severity']}({r['score']})")
    for e in r['errors']:
        print(f"       -> {e}")
    print()

total = len(SAMPLES)
print(f"={('='*60)}")
print(f"  RESULTADO FINAL: {passed}/{total} PASS  |  {failed}/{total} FAIL")
print(f"={('='*60)}")

with open('tests/reporte_normalizador_v2.json', 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nReporte JSON guardado en tests/reporte_normalizador_v2.json")
