"""Tool definitions for LLM function calling."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "exec",
            "description": "Run a shell command in the VM. Use for any file operations, package installs, service management, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "reason": {"type": "string", "description": "Brief explanation of why"},
                },
                "required": ["command", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enforce",
            "description": "Block or allow access via eBPF LSM or XDP. Use for security enforcement.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hook": {"type": "string", "description": "LSM hook or XDP action (e.g., file_open, socket_connect, xdp_drop)"},
                    "target": {"type": "string", "description": "Target to enforce on (file path, IP, etc.)"},
                    "action": {"type": "string", "enum": ["deny", "allow"], "description": "Action to take"},
                    "reason": {"type": "string", "description": "Brief explanation"},
                },
                "required": ["hook", "target", "action", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "transform",
            "description": "Rewrite packets or redirect traffic via XDP/TC.",
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Network interface"},
                    "match": {"type": "string", "description": "Traffic match rule"},
                    "rewrite": {"type": "string", "description": "Rewrite rule"},
                    "reason": {"type": "string", "description": "Brief explanation"},
                },
                "required": ["interface", "match", "rewrite", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "schedule",
            "description": "Set CPU scheduling priority for a process or cgroup via sched_ext.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "PID or cgroup path"},
                    "priority": {"type": "string", "description": "Priority class (e.g., latency-sensitive, batch, normal)"},
                    "reason": {"type": "string", "description": "Brief explanation"},
                },
                "required": ["target", "priority", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "measure",
            "description": "Read performance counters for a process.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "PID or process name"},
                    "metric": {"type": "string", "description": "Metric to measure (cache_misses, cycles, bandwidth)"},
                    "duration": {"type": "string", "description": "Duration (e.g., 5s, 1m)"},
                },
                "required": ["target", "metric"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kv_get",
            "description": "Read a value from shared state (NATS KV).",
            "parameters": {
                "type": "object",
                "properties": {
                    "bucket": {"type": "string", "description": "KV bucket (agents, tasks, policies, logs)"},
                    "key": {"type": "string", "description": "Key to read"},
                },
                "required": ["bucket", "key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kv_put",
            "description": "Write a value to shared state (NATS KV).",
            "parameters": {
                "type": "object",
                "properties": {
                    "bucket": {"type": "string", "description": "KV bucket"},
                    "key": {"type": "string", "description": "Key to write"},
                    "value": {"type": "object", "description": "JSON value to store"},
                },
                "required": ["bucket", "key", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kv_keys",
            "description": "List all keys in a shared state bucket.",
            "parameters": {
                "type": "object",
                "properties": {
                    "bucket": {"type": "string", "description": "KV bucket"},
                },
                "required": ["bucket"],
            },
        },
    },
]
