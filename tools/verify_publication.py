"""Read-only verification of the curated, publicly distributed snapshot."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = root / 'docs/reproducibilidade/publication_manifest.json'
if not manifest.is_file():
    raise SystemExit('Execute na copia publicada, que contem publication_manifest.json.')
entries = json.loads(manifest.read_text(encoding='utf-8'))['files']
errors = []
for item in entries:
    path = root / item['path']
    if not path.is_file():
        errors.append(item['path'] + ': missing')
        continue
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != item['published_sha256']:
        errors.append(item['path'] + ': hash mismatch')
if errors:
    raise SystemExit('\n'.join(errors))
print(f'OK: {len(entries)} published files verified. No data were modified.')
