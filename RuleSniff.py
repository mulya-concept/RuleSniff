import re
import sys
import os
import hashlib
from datetime import datetime

# ──────────────────────────────────────────────
# ════════════════ UTILITIES ═══════════════════
# ──────────────────────────────────────────────

def banner(title):
    line = "═" * (len(title) + 6)
    return f"\n╔{line}╗\n║   {title}   ║\n╚{line}╝\n"

def get_file_info(path, data):
    return {
        "name": os.path.basename(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def print_ascii_output(info, results):
    print(f"Target File : {info['name']}")
    print(f"SHA256      : {info['sha256']}")
    print(f"File Size   : {info['size']:,} bytes")
    print(f"Scan Time   : {info['time']}\n")

    print("╔" + "═"*54 + "╗")
    print("║                    MATCHED RULES                   ║")
    print("╚" + "═"*54 + "╝")

    if not results:
        print("No rules matched. File appears clean.")
        return

    print("┌────────────────────────────┬───────────────┐")
    print("│ Rule Name                  │ Offset(s)     │")
    print("├────────────────────────────┼───────────────┤")
    for name, matches in results:
        offsets = ", ".join([f"0x{m['offset']:X}" for m in matches])
        print(f"│ {name:<26} │ {offsets:<13} │")
    print("└────────────────────────────┴───────────────┘\n")

    print("📌 Details:")
    for name, matches in results:
        print(f"  • {name}:")
        for m in matches:
            val = m['value']
            decoded = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else val
            print(f"     - {m['ident']} matched at 0x{m['offset']:X}: \"{decoded}\"")

    print("\n═══════════════════════════════════════════════════════")
    print(f"🧾 Summary:")
    print(f"  ✔ Rules Matched  : {len(results)}")
    print(f"  ✔ Total Matches  : {sum(len(m[1]) for m in results)}")
    print("  ✔ Verdict        : ⚠️ Suspicious - Manual Analysis Recommended")
    print("═══════════════════════════════════════════════════════")

# ──────────────────────────────────────────────
# ════════════════ SCANNER LOGIC ═══════════════
# ──────────────────────────────────────────────

def parse_rules(rule_path):
    with open(rule_path, "r") as f:
        content = f.read()

    rules = []
    rule_blocks = re.findall(r'rule\s+(\w+)\s*{(.*?)}', content, re.DOTALL)

    for name, body in rule_blocks:
        strings = re.findall(r'\$(\w+)\s*=\s*(?:"([^"]+)"|{([^}]+)})', body)
        condition = re.search(r'condition:\s*(.+)', body)
        rule_obj = {
            "name": name,
            "strings": [],
            "condition": condition.group(1).strip() if condition else ""
        }

        for ident, s1, s2 in strings:
            value = s1 if s1 else s2
            rule_obj["strings"].append(("$" + ident, value.strip()))

        rules.append(rule_obj)
    return rules

def match_string(data, pattern):
    if re.fullmatch(r'[0-9A-Fa-f ]+', pattern):  # hex pattern
        try:
            hex_bytes = bytes.fromhex(pattern)
            return [(m.start(), hex_bytes) for m in re.finditer(re.escape(hex_bytes), data)]
        except:
            return []
    else:
        return [(m.start(), pattern) for m in re.finditer(re.escape(pattern.encode()), data)]

def scan_file(filepath, rule_path):
    rules = parse_rules(rule_path)
    with open(filepath, "rb") as f:
        data = f.read()

    file_info = get_file_info(filepath, data)
    results = []

    for rule in rules:
        matches = []
        for ident, pattern in rule["strings"]:
            match_locs = match_string(data, pattern)
            for offset, val in match_locs:
                matches.append({
                    "ident": ident,
                    "offset": offset,
                    "value": val
                })

        condition = rule["condition"]
        if condition == "all of them":
            if len(matches) >= len(rule["strings"]):
                results.append((rule["name"], matches))
        else:
            if matches:
                results.append((rule["name"], matches))

    print_ascii_output(file_info, results)

# ──────────────────────────────────────────────
# ══════════════════ MAIN ENTRY ════════════════
# ──────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python RuleSniff.py <target_file> <rule_file>")
        sys.exit(1)

    target_file = sys.argv[1]
    rule_file = sys.argv[2]

    print(banner(" MALWARE SCAN REPORT"))
    scan_file(target_file, rule_file)
