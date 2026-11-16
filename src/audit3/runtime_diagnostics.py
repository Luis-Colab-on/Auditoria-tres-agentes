"""Protocol rejection metadata only. Never persist wire frames or item content."""
from .agents import RuntimePaused
from .security import object_hash

VERSION = 'runtime-protocol-diagnostic-1'
# Names from the pinned 0.167.0 ThreadItem contract, not an execution allowlist.
CONTRACT_ITEM_TYPES = frozenset({
    'userMessage', 'hookPrompt', 'agentMessage', 'functionCallOutput', 'plan',
    'reasoning', 'commandExecution', 'fileChange', 'mcpToolCall', 'dynamicToolCall',
    'collabAgentToolCall', 'subAgentActivity', 'webSearch', 'imageView', 'sleep',
    'imageGeneration', 'enteredReviewMode', 'exitedReviewMode', 'contextCompaction'})
KNOWN_METHODS = frozenset({'item/started', 'item/completed', 'item/tool/call',
    'turn/started', 'turn/completed', 'thread/tokenUsage/updated',
    'item/commandExecution/requestApproval', 'item/fileChange/requestApproval',
    'item/tool/requestUserInput', 'account/chatgptAuthTokens/refresh'})
TOOL_NAMES = frozenset({'list_source', 'read_source', 'search_source', 'read_evidence', 'submit_test'})


class ProtocolViolation(RuntimePaused):
    def __init__(self, message, metadata):
        super().__init__(message)
        self.metadata = metadata


def rejection(message, reason, msg, context, thread_id, turn_id, steps, limit):
    params = msg.get('params')
    params = params if isinstance(params, dict) else {}
    item = params.get('item')
    item = item if isinstance(item, dict) else {}
    metadata = {'version': VERSION, 'reason': reason, 'role': context.role,
        'phase': context.phase, 'attempt': context.attempt,
        'invocation_id': context.invocation_id, 'thread_id': thread_id, 'turn_id': turn_id,
        'tool_requests': steps, 'tool_limit': limit}
    # Unknown names and peer-controlled identifiers are hashes, not free text.
    for key, value, known in (('method', msg.get('method'), KNOWN_METHODS),
                             ('item_type', item.get('type'), CONTRACT_ITEM_TYPES),
                             ('tool', params.get('tool'), TOOL_NAMES)):
        metadata[key] = value if isinstance(value, str) and value in known else None
        if value is not None and metadata[key] is None:
            metadata[key + '_sha256'] = object_hash(value)
    for key, value in (('request_id', msg.get('id')), ('item_id', item.get('id')),
                       ('reported_thread_id', params.get('threadId')), ('reported_turn_id', params.get('turnId'))):
        if value is not None:
            metadata[key + '_sha256'] = object_hash(value)
    return ProtocolViolation(message, metadata)
