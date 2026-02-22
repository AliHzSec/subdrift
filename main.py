import argparse
import re
import string
import sys
from itertools import combinations_with_replacement
from typing import List, Set

import datrie
import editdistance
import tldextract
from dank.DankEncoder import DankEncoder
from dank.DankGenerator import DankGenerator

MEMO = {}
DNS_CHARS = string.ascii_lowercase + string.digits + "._-"


class Colors:
    RESET = "\033[0m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"


class Logger:
    silent = False

    @staticmethod
    def info(message: str):
        if Logger.silent:
            return
        print(f"{Colors.BLUE}[INF]{Colors.RESET} {message}", file=sys.stderr)

    @staticmethod
    def success(message: str):
        if Logger.silent:
            return
        print(f"{Colors.GREEN}[SUC]{Colors.RESET} {message}", file=sys.stderr)

    @staticmethod
    def warning(message: str):
        if Logger.silent:
            return
        print(f"{Colors.YELLOW}[WRN]{Colors.RESET} {message}", file=sys.stderr)

    @staticmethod
    def error(message: str):
        if Logger.silent:
            return
        print(f"{Colors.RED}[ERR]{Colors.RESET} {message}", file=sys.stderr)

    @staticmethod
    def fatal(message: str):
        print(f"{Colors.RED}[FTL]{Colors.RESET} {message}", file=sys.stderr)
        sys.exit(1)

    @staticmethod
    def index(message: str):
        if Logger.silent:
            return
        print(f"{Colors.CYAN}[IDX]{Colors.RESET} {message}", file=sys.stderr)

    @staticmethod
    def debug(message: str):
        if Logger.silent:
            return
        print(f"{Colors.MAGENTA}[DBG]{Colors.RESET} {message}", file=sys.stderr)


def edit_closures(items: List[str], delta: int = 5) -> List[Set[str]]:
    """computes all subsets of items bounded by fixed edit distance"""
    global MEMO
    ret = []
    for a in items:
        found = False
        r = set([a])
        for b in items:
            dist = MEMO[a + b] if a + b in MEMO else MEMO[b + a]
            if dist < delta:
                r.add(b)
        for s in ret:
            if r == s:
                found = True
                break
        if not found:
            ret.append(r)
    return ret


def tokenize(items: List[str]):
    """tokenize DNS hostnames into leveled word tokens"""
    ret = []
    hosts = []
    for item in items:
        t = tldextract.extract(item)
        hosts.append(t.subdomain)
    labels = [host.split(".") for host in hosts]
    for label in labels:
        n = []
        for item in label:
            t = []
            tokens = [f"-{e}" if i != 0 else e for i, e in enumerate(item.split("-"))]
            for token in tokens:
                subtokens = [x for x in re.split("([0-9]+)", token) if len(x) > 0]
                for i in range(len(subtokens)):
                    if subtokens[i] == "-" and i + 1 < len(subtokens):
                        subtokens[i + 1] = "-" + subtokens[i + 1]
                    else:
                        t.append(subtokens[i])
            n.append(t)
        ret.append(n)
    return ret


def compress_number_ranges(regex: str) -> str:
    """given an 'uncompressed' regex, returns a regex with ranges instead"""
    ret = regex[:]
    stack, groups, repl, extra, hyphen = [], [], {}, {}, {}
    for i, e in enumerate(regex):
        if e == "(":
            stack.append(i)
        elif e == ")":
            start = stack.pop()
            group = regex[start + 1 : i]
            tokens = group.split("|")
            numbers = [token for token in tokens if token.isnumeric()]
            nonnumbers = [token for token in tokens if not token.isnumeric() and not re.match("-[0-9]+", token)]
            hyphenatednumbers = [token[1:] for token in tokens if re.match("-[0-9]+", token)]
            if "?" in group or ")" in group or "(" in group:
                continue
            elif len(numbers) != 0 and len(hyphenatednumbers) != 0:
                continue
            elif len(numbers) > 1:
                g1 = "|".join(numbers)
                g2 = "|".join(nonnumbers)
                repl[g1] = group
                extra[g1] = g2
                groups.append(g1)
            elif len(hyphenatednumbers) > 1:
                g1 = "|".join(hyphenatednumbers)
                g2 = "|".join(nonnumbers)
                repl[g1] = group
                extra[g1] = g2
                groups.append(g1)
                hyphen[g1] = True
    for group in groups:
        generalized = "(" if not group in hyphen else "(-"
        positions = {}
        tokens = [g[::-1] for g in group.split("|")]
        for token in tokens:
            for position, symbol in enumerate(token):
                if not position in positions:
                    positions[position] = set([])
                positions[position].add(int(symbol))
        s = sorted(tokens, key=lambda x: len(x))
        start, end = len(s[-1]) - 1, len(s[0]) - 1
        for i in range(start, end, -1):
            positions[i].add(None)
        for i, symbols in sorted(positions.items(), key=lambda x: x[0], reverse=True):
            optional = None in symbols
            if optional:
                symbols.remove(None)
            s = sorted(symbols)
            start, end = s[0], s[-1]
            if start != end:
                generalized += f'[{start}-{end}]{"?" if optional else ""}'
            else:
                generalized += f'{start}{"?" if optional else ""}'
        generalized += ")"
        ext = extra[group]
        rep = repl[group]
        if ext != "":
            generalized = f"({generalized}|({ext}))"
        ret = ret.replace(f"({rep})", generalized)
    return ret


def closure_to_regex(domain: str, members: List[str]) -> str:
    """converts edit closure to a regular language"""
    ret, levels, optional = "", {}, {}
    tokens = tokenize(members)
    for member in tokens:
        for i, level in enumerate(member):
            if i not in levels:
                levels[i] = {}
                optional[i] = {}
            for j, token in enumerate(level):
                if not j in levels[i]:
                    levels[i][j] = set([])
                    optional[i][j] = []
                levels[i][j].add(token)
                optional[i][j].append(token)
    for i, level in enumerate(levels):
        n = "(." if i != 0 else ""
        for j, position in enumerate(levels[level]):
            k = len(levels[level][position])
            if i == 0 and j == 0:
                n += f"({'|'.join(levels[level][position])})"
            elif k == 1 and j == 0:
                n += f"{'|'.join(levels[level][position])}"
            else:
                isoptional = len(optional[level][position]) != len(members)
                n += f"({'|'.join(levels[level][position])}){'?' if isoptional else ''}"
        values = list(map(lambda x: "".join(x), zip(*optional[level].values())))
        isoptional = len(set(values)) != 1 or len(values) != len(members)
        ret += (n + ")?" if isoptional else n + ")") if i != 0 else n
    return compress_number_ranges(f"{ret}.{domain}")


def is_good_rule(regex: str, nkeys: int, threshold: int, max_ratio: float) -> bool:
    """applies ratio test to determine if a rule is acceptable"""
    e = DankEncoder(regex, 256)
    nwords = e.num_words(1, 256)
    return nwords < threshold or (nwords / nkeys) < max_ratio


def sort_and_unique(lines: List[str]) -> List[str]:
    return sorted(set(lines))


def main():
    global DNS_CHARS, MEMO

    parser = argparse.ArgumentParser(description="SubDrift - Automated regex learning for DNS discovery")
    parser.add_argument("-d", "--domain", required=True, type=str, help="Target root domain (e.g. example.com)")
    parser.add_argument("-i", "--input", required=True, type=str, help="Input file containing observed hostnames")
    parser.add_argument("-o", "--output", required=False, type=str, help="Output file for generated candidates (optional)")
    parser.add_argument("-sr", "--save-rules", required=False, type=str, help="Save generated transformation rules to file (optional)")
    parser.add_argument("-th", "--threshold", required=False, type=int, default=500, help="Max number of synthetic words allowed per rule (default: 500)")
    parser.add_argument("-mr", "--max-ratio", required=False, type=float, default=25.0, help="Max allowed ratio of synthetic to observed hostnames (default: 25.0)")
    parser.add_argument("-ml", "--max-length", required=False, type=int, default=1000, help="Max character length for a generated rule (default: 1000)")
    parser.add_argument("-dl", "--dist-low", required=False, type=int, default=2, help="Minimum edit distance for grouping hostnames (default: 2)")
    parser.add_argument("-dh", "--dist-high", required=False, type=int, default=10, help="Maximum edit distance for grouping hostnames (default: 10)")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode - suppress all log output")
    args = vars(parser.parse_args())

    if args["silent"]:
        Logger.silent = True

    Logger.info(f"SubDrift starting: domain={args['domain']} max_ratio={args['max_ratio']} threshold={args['threshold']}")

    trie = datrie.Trie(DNS_CHARS)
    known_hosts, new_rules = set([]), set([])

    def first_token(item: str):
        tokens = tokenize([item])
        return tokens[0][0][0]

    try:
        with open(args["input"], "r") as handle:
            known_hosts = sorted(list(set([line.strip() for line in handle.readlines()])))
    except FileNotFoundError:
        Logger.fatal(f"Input file not found: {args['input']}")

    valid_hosts = []
    for host in known_hosts:
        if host != args["domain"]:
            tokens = tokenize([host])
            if len(tokens) > 0 and len(tokens[0]) > 0 and len(tokens[0][0]) > 0:
                trie[host] = True
                valid_hosts.append(host)
            else:
                Logger.warning(f"Rejecting malformed input: {host}")
    known_hosts = valid_hosts

    Logger.success(f"Loaded {len(known_hosts)} observations")
    Logger.info("Building table of all pairwise distances...")

    for s, t in combinations_with_replacement(known_hosts, 2):
        MEMO[s + t] = editdistance.eval(s, t)

    Logger.success("Pairwise distance table built")

    # No enforced prefix
    for k in range(args["dist_low"], args["dist_high"]):
        Logger.info(f"Edit distance pass: k={k}")
        closures = edit_closures(known_hosts, delta=k)
        for closure in closures:
            if len(closure) > 1:
                r = closure_to_regex(args["domain"], closure)
                if len(r) > args["max_length"]:
                    continue
                if r not in new_rules and is_good_rule(r, len(closure), args["threshold"], args["max_ratio"]):
                    new_rules.add(r)

    # Unigrams + bigrams as fixed prefixes
    ngrams = sorted(list(set(DNS_CHARS) | set(["".join([i, j]) for i in DNS_CHARS for j in DNS_CHARS])))
    for ngram in ngrams:
        keys = trie.keys(ngram)
        if len(keys) == 0:
            continue

        r = closure_to_regex(args["domain"], keys)
        if r not in new_rules and is_good_rule(r, len(keys), args["threshold"], args["max_ratio"]):
            new_rules.add(r)

        last, prefixes = None, sorted(list(set([first_token(k) for k in trie.keys(ngram)])))
        for prefix in prefixes:
            keys = trie.keys(prefix)

            r = closure_to_regex(args["domain"], keys)
            if r not in new_rules and is_good_rule(r, len(keys), args["threshold"], args["max_ratio"]):
                if last is None or not prefix.startswith(last):
                    last = prefix
                else:
                    Logger.warning(f"Rejecting redundant prefix: {prefix}")
                    continue
                new_rules.add(r)

            if len(prefix) > 1:
                for k in range(args["dist_low"], args["dist_high"]):
                    closures = edit_closures(keys, delta=k)
                    for closure in closures:
                        r = closure_to_regex(args["domain"], closure)
                        if r not in new_rules and is_good_rule(r, len(closure), args["threshold"], args["max_ratio"]):
                            new_rules.add(r)
                        elif r not in new_rules:
                            Logger.error(f"Rule cannot be processed: {r}")

    # Generate all candidates from rules
    Logger.info("Generating candidates from rules...")
    candidates = []
    for line in new_rules:
        for item in DankGenerator(line.strip()):
            candidates.append(item.decode("utf-8") + "\n")

    # Sort, unique, and fix malformed subdomains
    candidates = sort_and_unique(candidates)
    candidates = sorted(set(map(lambda line: re.sub(r"\.{2,}", ".", line), candidates)))

    Logger.success(f"Generated {len(candidates)} unique candidates")

    # Save rules file if --save-rules is provided
    if args["save_rules"]:
        try:
            with open(args["save_rules"], "w") as handle:
                for rule in new_rules:
                    handle.write(f"{rule}\n")
            Logger.info(f"Rules saved to: {args['save_rules']}")
        except IOError as e:
            Logger.error(f"Failed to write rules file: {str(e)}")

    # Output candidates to stdout
    for candidate in candidates:
        print(candidate, end="")

    # Save to file if --output is provided
    if args["output"]:
        try:
            with open(args["output"], "w") as handle:
                handle.writelines(candidates)
            Logger.success(f"Output saved to: {args['output']}")
        except IOError as e:
            Logger.error(f"Failed to write output file: {str(e)}")


if __name__ == "__main__":
    main()
