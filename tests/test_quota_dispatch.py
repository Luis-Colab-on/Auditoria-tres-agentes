"""Queued official observations, simulated transport only; no account operations."""
import asyncio
import copy
import pytest
from audit3.agents import RuntimePaused
from test_codex_runtime import rig, QUOTA
from test_runtime_tool_budget import controlled_clock


@pytest.mark.parametrize('kind', ['ordinary', 'window', 'credits', 'spend'])
def test_received_blocking_quota_update_prevents_new_turn(make_run, kind):
    store, m, runtime, rpc, tools = rig(make_run)
    update = copy.deepcopy(QUOTA)
    if kind == 'ordinary': update['ordinaryUsageAllowed'] = False
    if kind == 'window': update['rateLimits']['primary']['usedPercent'] = 100
    if kind == 'credits': update['rateLimits']['credits']['hasCredits'] = True
    if kind == 'spend': update['rateLimits']['spendControlReached'] = True
    rpc.events.put_nowait({'method': 'account/rateLimits/updated', 'params': update})
    with pytest.raises(RuntimePaused):
        asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    assert not any(method == 'turn/start' for method, _ in rpc.calls)


def test_notification_arriving_at_dispatch_guard_blocks_without_write(make_run):
    store, m, runtime, rpc, tools = rig(make_run)
    original = rpc.request
    async def inject(method, params, **kwargs):
        if method == 'turn/start':
            rpc.events.put_nowait({'method': 'account/rateLimits/updated', 'params': {'ordinaryUsageAllowed': False}})
        return await original(method, params, **kwargs)
    rpc.request = inject
    with pytest.raises(RuntimePaused):
        asyncio.run(runtime.invoke('auditor', 'initial-0000', {}, tools))
    assert not any(method == 'turn/start' for method, _ in rpc.calls)
    cp = store.get(m.run_id, 'codex-turns/' + tools.context.invocation_id)
    assert cp['status'] == 'not_sent' and cp['dispatch_status'] == 'not_sent'
    assert len(store.get(m.run_id, 'ledger')['calls']) == 1
