import re

import ahocorasick

# Strip regex escape sequences (\, B, w, d, s, S, ., +, *, ?, |, (, ), [, ], {, }, n, t, r, etc.)
# before extracting literal words so that \bexec yields exec not bexec.
_CLEAN_RE = re.compile(r"\\.")

_LITERAL_EXTRACTOR = re.compile(r"\b([A-Za-z_]\w{3,})\b")

_SKIP_WORDS = frozenset(
    {
        "or",
        "and",
        "not",
        "int",
        "str",
        "char",
        "hex",
        "md5",
        "set",
        "get",
        "put",
        "post",
        "len",
        "max",
        "min",
        "sub",
        "del",
        "key",
        "val",
        "tmp",
        "src",
        "dst",
        "ref",
        "abs",
        "var",
        "arg",
        "out",
        "buf",
        "msg",
        "log",
        "seq",
        "num",
        "sum",
        "avg",
        "cnt",
        "idx",
        "pos",
        "neg",
        "nil",
        "err",
    }
)


def _clean_pattern(pattern: str) -> str:
    """Remove backslash-escape sequences so literal-word extraction is not confused."""
    return _CLEAN_RE.sub(" ", pattern)


def extract_literals(pattern: str) -> list[str]:
    """Extract meaningful literal words (>=4 alpha chars) from a regex pattern.

    Returns lowercase deduplicated list of substrings that *must* typically
    appear in the input for the regex to match.  Rules with zero extracted
    literals will always be checked via the fallback path.
    """
    cleaned = _clean_pattern(pattern)
    seen: set[str] = set()
    result: list[str] = []
    for m in _LITERAL_EXTRACTOR.finditer(cleaned):
        word = m.group(1).lower()
        if word in _SKIP_WORDS or len(word) < 4:
            continue
        if word not in seen:
            seen.add(word)
            result.append(word)
    return result


class AhoCorasickMatcher:
    """Multi-pattern matcher using Aho-Corasick automaton for rule pre-filtering.

    The automaton indexes literal keywords extracted from each rule's regex.
    ``find_candidates()`` returns the set of rule_ids whose keywords appear
    in the input text.  Rules with zero extractable keywords are always
    returned (fallback) so the caller can still run the full regex.
    """

    def __init__(self) -> None:
        self._automaton: ahocorasick.Automaton | None = None
        self._keyword_to_rules: dict[str, set[str]] = {}
        self._fallback_rule_ids: set[str] = set()
        self._built = False

    def build(self, rules: list[dict]) -> None:
        """Build/re-build the AC trie from the active rules list.

        Each rule dict must have ``rule_id`` and ``pattern`` keys.
        """
        self._keyword_to_rules.clear()
        keyword_map: dict[str, set[str]] = {}
        self._fallback_rule_ids.clear()

        for rule in rules:
            rid = rule["rule_id"]
            literals = extract_literals(rule["pattern"])
            if not literals:
                self._fallback_rule_ids.add(rid)
                continue
            for kw in literals:
                keyword_map.setdefault(kw, set()).add(rid)

        if not keyword_map:
            self._automaton = None
            self._built = True
            return

        automaton = ahocorasick.Automaton()
        for keyword, rule_ids in keyword_map.items():
            automaton.add_word(keyword, (keyword, rule_ids))
        automaton.make_automaton()

        self._automaton = automaton
        self._keyword_to_rules = keyword_map
        self._built = True

    def find_candidates(self, text: str) -> set[str]:
        """Return the set of rule_ids that *might* match the input text.

        Includes all fallback rules.  Returns an empty set when the automaton
        has not been built yet (no rules loaded), which signals the caller
        to fall back to the full per-rule regex loop.
        """
        if not self._built:
            return set()
        if self._automaton is None:
            # No extractable keywords at all → every rule is a fallback
            return set(self._fallback_rule_ids)

        candidates: set[str] = set()
        text_lower = text.lower()
        for _, (_keyword, rule_ids) in self._automaton.iter(text_lower):
            candidates.update(rule_ids)
        candidates.update(self._fallback_rule_ids)
        return candidates

    @property
    def is_built(self) -> bool:
        return self._built

    @property
    def stats(self) -> dict:
        return {
            "keywords": len(self._keyword_to_rules),
            "fallback_rules": len(self._fallback_rule_ids),
            "total_nodes": len(self._automaton) if self._automaton else 0,
        }


AUTOMATON = AhoCorasickMatcher()
