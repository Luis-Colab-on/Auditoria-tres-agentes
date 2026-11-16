"""Read-only initial batch plan. No client, Docker, account queries or inference."""
import argparse
import json
from pathlib import Path
from audit3.reprocess import ReadOnlyStore
from audit3.workflow import Workflow
from audit3.snapshot import verify_source
from audit3.turn_planning import source_plans, VERSION


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, default=Path('.audit3'))
    parser.add_argument('--run', required=True)
    parser.add_argument('--output', type=Path, required=True, help='new file outside the run store')
    args = parser.parse_args(argv)
    store = ReadOnlyStore(args.store)
    if args.output.resolve().is_relative_to(store.root):
        parser.error('output must be outside the preserved run store')
    workflow = Workflow(store, args.run)
    verify_source(store, workflow.manifest)
    entries = source_plans(store, workflow.manifest, workflow.config)
    blocked = [{'role': e['role'], 'phase': e['phase'],
                'minimum_source_calls': e['plan']['minimum_tool_calls'],
                'unreadable_lines': e['plan']['unreadable_lines']}
               for e in entries if not e['plan']['mandatory_reads_fit']]
    result = {'version': VERSION, 'run_id': args.run, 'source_id': workflow.manifest.source_id,
              'generation_requests': 0, 'max_tool_calls': workflow.config.limits.max_turns,
              'all_source_reads_fit': not blocked, 'blocked_batches': blocked, 'plans': entries,
              'interpretation': 'Lower bound for source reads, not semantic coverage or audit acceptance. '
                'Actual turns also plan missing baseline consultations. Judge retains directed blind inspection.'}
    with args.output.open('x') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps({k: result[k] for k in ('version', 'generation_requests', 'all_source_reads_fit', 'blocked_batches')}, ensure_ascii=False))
    return 0 if not blocked else 2


if __name__ == '__main__':
    raise SystemExit(main())
