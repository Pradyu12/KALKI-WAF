import re

from waf import state


def reload_rules_cache():
    from waf.db import query_db

    rules = query_db("SELECT * FROM rules WHERE is_active = 1")
    cache = []
    if rules:
        for r in rules:
            try:
                pattern = r["pattern"]
                compiled = re.compile(pattern, re.IGNORECASE)
                cache.append(
                    {
                        "rule_id": r["rule_id"],
                        "identifier": r["identifier"],
                        "pattern": pattern,
                        "action": r["action"],
                        "category": r["category"],
                        "compiled_regex": compiled,
                    }
                )
            except Exception as e:
                print(f"[WARN] Failed to compile regex for security profile '{r['identifier']}': {e}")
    state.ACTIVE_RULES_CACHE[:] = cache
    print(
        f"[INFO] Threat Engine: Active rule clusters synchronized ({len(state.ACTIVE_RULES_CACHE)} loaded in memory)."
    )  # noqa: E501


def reload_global_posture():
    from waf.db import query_db

    row = query_db("SELECT posture FROM mitigation_state WHERE id = 'global'", one=True)
    state.GLOBAL_POSTURE = row["posture"] if row else "Standard Posture"
    print(f"[INFO] Threat Engine: Global operating posture synchronized -> {state.GLOBAL_POSTURE}")
