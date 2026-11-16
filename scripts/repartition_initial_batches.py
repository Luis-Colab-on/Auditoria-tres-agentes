"""Explicit local batch distribution; no client, Docker or generation."""
import argparse
import json
from pathlib import Path
from audit3.reprocess import ReadOnlyStore
from audit3.workflow import Workflow
from audit3.batch_distribution import build_distribution, register_distribution
from audit3.snapshot import verify_source
from audit3.evidence import Store


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, default=Path('.audit3'))
    parser.add_argument('--run', required=True)
    parser.add_argument('--reviewer', required=True)
    parser.add_argument('--output', type=Path, required=True, help='new candidate file outside Store')
    parser.add_argument('--apply', action='store_true', help='register immutable distribution; explicit operator instruction required')
    args = parser.parse_args(argv)
    store = ReadOnlyStore(args.store)
    if args.output.resolve().is_relative_to(store.root):
        parser.error('output must remain outside Store')
    workflow = Workflow(store, args.run)
    verify_source(store, workflow.manifest)
    record = build_distribution(store, workflow.manifest, workflow.config, args.reviewer)
    with args.output.open('x') as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
        f.write('\n')
    if args.apply:
        register_distribution(Store(args.store), workflow.manifest, workflow.config, record)
    print(json.dumps({'distribution_id': record['id'], 'old_batches': len(record['original_batches']),
        'new_batches': len(record['batches']), 'applied': args.apply, 'generation_requests': 0}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
