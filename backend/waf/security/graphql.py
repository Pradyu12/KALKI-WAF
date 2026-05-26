from waf import config


def check_graphql_depth(query: str) -> bool:
    if not query:
        return True

    max_depth = 0
    current_depth = 0
    in_string = False
    in_argument = False
    i = 0
    while i < len(query):
        char = query[i]
        if char == '"' and (not in_string or query[max(0, i - 1)] != "\\"):
            in_string = not in_string
        elif not in_string:
            if char == "(":
                in_argument = True
                current_depth += 1
            elif char == ")":
                current_depth = max(0, current_depth - 1)
                in_argument = False
            elif char == "{" and not in_argument:
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == "}":
                current_depth = max(0, current_depth - 1)
        i += 1

    return max_depth <= config.GRAPHQL_MAX_DEPTH
