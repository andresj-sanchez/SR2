#!/usr/bin/env python3
"""
analyze_mwcc.py — Mine MWCC compiler behaviour from permuter trial data.

Usage:
  python tools/analyze_mwcc.py research/mwcc_trials.jsonl [--verbose]
  python tools/analyze_mwcc.py research/mwcc_trials.jsonl --validate
"""

import json
import os
import re
import subprocess
import sys
import collections
from typing import List, Dict, Tuple, Optional


# ─── Load ─────────────────────────────────────────────────────────────────────

def load(path: str):
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


# ─── Helpers ──────────────────────────────────────────────────────────────────

def pearson(xs: List[float], ys: List[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx  = (sum((x - mx) ** 2 for x in xs)) ** 0.5
    dy  = (sum((y - my) ** 2 for y in ys)) ** 0.5
    return num / (dx * dy) if dx * dy > 0 else 0.0


def get_pos(lines: List[str], predicate) -> int:
    for i, l in enumerate(lines):
        if predicate(l):
            return i
    return -1


def mnemonic(instr: str) -> str:
    parts = instr.strip().split()
    return parts[0] if parts else ''


# ─── Source feature extraction ────────────────────────────────────────────────

# Predicates for key lines
_LINE_PREDS = {
    'u32Ability_base':  lambda l: 'u32Ability = rcBase' in l,
    'u32Ability_walk':  lambda l: 'u32Ability = 0' in l,
    'Limit_call':       lambda l: 'Limit(this->m_sWalk)' in l,
    'weight_assign':    lambda l: 'm_f32WeightRate' in l and '=' in l,
    'JumpSpeed_base':   lambda l: 'm_sBase.f32JumpSpeed' in l,
    'JumpAccele_base':  lambda l: 'm_sBase.f32JumpAccele' in l,
    'first_base_speed': lambda l: 'm_sBase.f32Speed[0]' in l,
    'weight_temp':      lambda l: bool(re.match(r'\s*float \w+ = psVar2->', l)),
    'AdjustSpeed_def':  lambda l: 'f32AdjustSpeedRate' in l and 'float' in l,
    'AdjustCurve_def':  lambda l: 'f32AdjustCurveRate' in l and 'float' in l,
}


def extract_features(entry: dict) -> Dict:
    lines  = entry['regions']['group0']
    instrs = entry['instructions'] or []
    f = {}

    # ── Positions of key source lines ────────────────────────────────────────
    positions = {k: get_pos(lines, pred)
                 for k, pred in _LINE_PREDS.items()}
    f.update({f'pos_{k}': v for k, v in positions.items()})

    # ── Relative orderings that matter ───────────────────────────────────────
    pa = positions
    def gap(a, b):
        return pa[b] - pa[a] if pa[a] >= 0 and pa[b] >= 0 else None

    # Weight comes after first_base_speed? (hoisted base lines)
    g = gap('first_base_speed', 'weight_assign')
    f['weight_after_first_base'] = int(g > 0) if g is not None else 0
    f['weight_to_base_gap'] = g if g is not None else 0

    # JumpSpeed/JumpAccele hoisted before weight
    g2 = gap('weight_assign', 'JumpSpeed_base')
    f['jumpspeed_before_weight'] = int(g2 is not None and g2 < 0)

    # u32Ability_base hoisted before Limit call
    g3 = gap('u32Ability_base', 'Limit_call')
    f['ability_base_before_limit'] = int(g3 is not None and g3 < 0)

    # u32Ability_walk position (late = better based on data)
    f['ability_walk_pos'] = pa['u32Ability_walk']

    # ── Split form usage ──────────────────────────────────────────────────────
    # Count lines that are standalone preloads (float fVarN = src->field)
    n_preload = sum(
        1 for l in lines
        if re.match(r'\s*float \w+ = \w+[\.\[]', l)
        and 'this->' not in l
        and re.search(r'[\.\[]', l)
        and '+' not in l and '-' not in l
    )
    # Count lines that are stores using a temp (this->x = rate * fVarN)
    n_split_store = sum(
        1 for l in lines
        if re.match(r'\s*this->\S+ = \w+ \* f\w+\s*;', l)
    )
    # Count direct stores (this->x = src->field, no temp)
    n_direct = sum(
        1 for l in lines
        if re.match(r'\s*this->\S+ = \w+[\.\[]', l)
        and '*' not in l
    )
    f['n_preload_lines']   = n_preload
    f['n_split_stores']    = n_split_store
    f['n_direct_stores']   = n_direct
    f['uses_weight_temp']  = int(positions['weight_temp'] >= 0)

    # Avg gap between preload and its store
    preload_vars: Dict[str, int] = {}
    gaps = []
    for i, line in enumerate(lines):
        m = re.match(r'\s*float (\w+) = [^;]+;', line)
        if m and 'this->' not in line:
            preload_vars[m.group(1)] = i
        m2 = re.search(r'=\s*\w+\s*\*\s*(f\w+)\s*;', line)
        if m2 and 'this->' in line and m2.group(1) in preload_vars:
            gaps.append(i - preload_vars[m2.group(1)])
    f['avg_preload_gap'] = sum(gaps) / len(gaps) if gaps else 0.0
    f['max_preload_gap'] = max(gaps) if gaps else 0
    f['n_gaps']          = len(gaps)

    # ── Assembly features ─────────────────────────────────────────────────────
    mnems = [mnemonic(i) for i in instrs]
    f['n_instrs']   = len(instrs)
    f['n_nops']     = mnems.count('nop')
    f['n_lwc1']     = mnems.count('lwc1')
    f['n_swc1']     = mnems.count('swc1')
    f['n_lui']      = mnems.count('lui')
    f['n_mul_s']    = mnems.count('mul.s')
    f['n_mtc1']     = mnems.count('mtc1')

    # Distinct FP registers used
    fp_regs = set()
    for instr in instrs:
        for reg in re.findall(r'\bf\d+\b', instr):
            fp_regs.add(reg)
    f['n_distinct_fp_regs'] = len(fp_regs)

    # Load-then-multiply ratio (good pattern)
    lwc1_then_mul = sum(
        1 for i in range(len(mnems) - 1)
        if mnems[i] == 'lwc1' and mnems[i+1] == 'mul.s'
    )
    f['lwc1_then_mul'] = lwc1_then_mul

    # mtc1 count (integer→FP moves, bad — means compiler couldn't keep in FP)
    f['mtc1_ratio'] = f['n_mtc1'] / max(f['n_instrs'], 1)

    return f


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    validate_mode = '--validate' in sys.argv
    cluster_mode  = '--cluster'  in sys.argv
    predict_mode  = '--predict'  in sys.argv
    verbose = '--verbose' in sys.argv
    path = next((a for a in sys.argv[1:] if not a.startswith('--')), None)
    if not path:
        print("Usage: python tools/analyze_mwcc.py research/mwcc_trials.jsonl [--validate] [--cluster] [--predict [src.cpp]]")
        sys.exit(1)

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    print(f"Loading {path}...")
    entries = load(path)
    scores  = [e['score'] for e in entries]
    print(f"Loaded {len(entries)} entries  "
          f"(min={min(scores):.1f}%  max={max(scores):.1f}%  "
          f"mean={sum(scores)/len(scores):.1f}%)\n")

    print("Extracting features...")
    feats = [extract_features(e) for e in entries]

    s_min, s_max = min(scores), max(scores)
    s_range = s_max - s_min
    # Auto-adapt thresholds so high/low are never empty
    hi_thresh = s_min + s_range * 0.75
    lo_thresh = s_min + s_range * 0.25
    high = [(e, f) for e, f in zip(entries, feats) if e['score'] >= hi_thresh]
    mid  = [(e, f) for e, f in zip(entries, feats)
            if lo_thresh <= e['score'] < hi_thresh]
    low  = [(e, f) for e, f in zip(entries, feats) if e['score'] < lo_thresh]
    print(f"  high(>={hi_thresh:.1f}%): {len(high)}"
          f"  mid: {len(mid)}"
          f"  low(<{lo_thresh:.1f}%): {len(low)}\n")

    # ── 1. Score distribution ─────────────────────────────────────────────────
    print("=" * 64)
    print("1. SCORE DISTRIBUTION")
    print("=" * 64)
    dist_buckets = collections.Counter(int(s // 5) * 5 for s in scores)
    for b in sorted(dist_buckets):
        bar = '█' * (dist_buckets[b] // 10)
        print(f"  {b:3d}-{b+4}%  {dist_buckets[b]:4d}  {bar}")
    print()

    # ── 2. Feature correlations ───────────────────────────────────────────────
    print("=" * 64)
    print("2. FEATURE CORRELATIONS WITH SCORE  (r=pearson)")
    print("=" * 64)
    feat_keys = [k for k in feats[0] if k not in ('n_instrs',)]
    corrs = []
    for k in feat_keys:
        vals = [f[k] for f in feats]
        if len(set(vals)) < 2:
            continue
        r = pearson(vals, scores)
        corrs.append((k, r))
    corrs.sort(key=lambda x: -abs(x[1]))

    print(f"  {'feature':<30s}  {'r':>7s}  direction")
    print(f"  {'-'*30}  {'-'*7}  {'-'*20}")
    for k, r in corrs:
        if abs(r) < 0.02:
            continue
        direction = ('↑ higher = better' if r > 0 else '↓ lower  = better')
        bar = ('█' if r > 0 else '░') * min(16, int(abs(r) * 20))
        print(f"  {k:<30s}  {r:+.3f}  {bar}  {direction}")
    print()

    # ── 3. Key ordering rules ─────────────────────────────────────────────────
    print("=" * 64)
    print("3. ORDERING RULES  (avg position: high vs low)")
    print("=" * 64)
    print(f"  {'line':<25s}  {'high82+'!s:>8s}  {'low<70'!s:>8s}  {'diff':>6s}  rule")
    print(f"  {'-'*25}  {'-------':>8s}  {'------':>8s}  {'----':>6s}")

    def avg_feat(group, key):
        vals = [f[key] for _, f in group if f[key] >= 0]
        return sum(vals) / len(vals) if vals else 0.0

    key_positions = [
        ('pos_u32Ability_base',  'u32Ability=rcBase',  'earlier = better'),
        ('pos_Limit_call',       'Limit(m_sWalk)',      'earlier = better'),
        ('pos_weight_assign',    'm_f32WeightRate=',    'later   = better'),
        ('pos_JumpSpeed_base',   'JumpSpeed_base',      'earlier = better'),
        ('pos_u32Ability_walk',  'u32Ability=0',        'later   = better'),
        ('pos_first_base_speed', 'first_base_speed',    'no clear rule'),
    ]
    for key, label, rule in key_positions:
        ha = avg_feat(high, key)
        la = avg_feat(low,  key)
        d  = ha - la
        print(f"  {label:<25s}  {ha:>8.1f}  {la:>8.1f}  {d:>+6.1f}  {rule}")
    print()

    # ── 4. Assembly rules ─────────────────────────────────────────────────────
    print("=" * 64)
    print("4. ASSEMBLY RULES")
    print("=" * 64)

    def avg_asm(group, key):
        return sum(f[key] for _, f in group) / len(group) if group else 0.0

    asm_keys = [
        ('n_nops',            'NOPs',              'target has exactly 10'),
        ('n_distinct_fp_regs','distinct FP regs',  'fewer = better (tighter regalloc)'),
        ('n_lwc1',            'lwc1 (FP loads)',   'fewer = better'),
        ('n_mtc1',            'mtc1 (int→FP)',     'fewer = better'),
        ('lwc1_then_mul',     'lwc1→mul.s pairs',  'more = better'),
        ('n_lui',             'lui (upper imm)',   'more = better (const loading)'),
    ]
    print(f"  {'metric':<25s}  {'high82+'!s:>8s}  {'low<70'!s:>8s}  {'diff':>6s}  note")
    print(f"  {'-'*25}  {'-------':>8s}  {'------':>8s}  {'----':>6s}")
    for key, label, note in asm_keys:
        ha = avg_asm(high, key)
        la = avg_asm(low,  key)
        d  = ha - la
        print(f"  {label:<25s}  {ha:>8.2f}  {la:>8.2f}  {d:>+6.2f}  {note}")
    print()

    # ── 5. The nop rule ───────────────────────────────────────────────────────
    print("=" * 64)
    print("5. NOP COUNT RULE  (critical finding)")
    print("=" * 64)
    score_by_nops: Dict[int, List[float]] = collections.defaultdict(list)
    for e, f in zip(entries, feats):
        score_by_nops[f['n_nops']].append(e['score'])
    print(f"  {'nops':<6s}  {'count':>6s}  {'avg_score':>10s}  {'min':>7s}  {'max':>7s}")
    for n in sorted(score_by_nops):
        sc = score_by_nops[n]
        print(f"  {n:<6d}  {len(sc):>6d}  "
              f"{sum(sc)/len(sc):>10.2f}%  "
              f"{min(sc):>7.2f}%  {max(sc):>7.2f}%")
    print()

    # ── 6. Actionable rules summary ───────────────────────────────────────────
    print("=" * 64)
    print("6. ACTIONABLE RULES FOR MWCC PS2 (this->x = rate * src->field)")
    print("=" * 64)
    rules = [
        ("RULE 1", "nops=10 is the target",
         "The original has exactly 10 NOPs. Any ordering producing 10 NOPs "
         "is on the right track. 9 NOPs = scheduling mismatch."),
        ("RULE 2", "fewer distinct FP regs = better",
         "High scores use fewer unique FP registers (tighter reuse). "
         "Aim for fv0/fv1/ft0 reuse pattern, not spreading across f4-f12."),
        ("RULE 3", "m_f32WeightRate should come LATE",
         "avg pos in high=25.8, low=21.4. Hoisting base lines BEFORE "
         "the weight assignment improves score significantly."),
        ("RULE 4", "u32Ability=rcBase should come EARLY",
         "avg pos in high=17.9, low=23.2 (diff=-5.3). "
         "This line should be hoisted well before the Limit call."),
        ("RULE 5", "u32Ability=0 (walk) should come LATE",
         "avg pos in high=38.4, low=29.2 (diff=+9.1). "
         "This line belongs near the end of the region."),
        ("RULE 6", "prefer lwc1→mul.s over mtc1→swc1",
         "High scores have more lwc1→mul.s pairs and fewer mtc1 instructions. "
         "mtc1 means the compiler moved a value through integer regs — "
         "a sign of suboptimal FP register allocation."),
        ("RULE 7", "more lui = better",
         "lui loads 16-bit constants. More lui in high scores means the "
         "compiler is loading float constants (1.0f etc) into FP regs "
         "earlier, matching the target's constant-loading strategy."),
    ]
    for name, title, detail in rules:
        print(f"\n  {name}: {title}")
        print(f"    {detail}")

    # ── 7. Best known orderings ───────────────────────────────────────────────
    print()
    print("=" * 64)
    print("7. TOP 5 HIGHEST SCORING ORDERINGS")
    print("=" * 64)
    top5 = sorted(zip(entries, feats), key=lambda x: -x[0]['score'])[:5]
    for i, (e, f) in enumerate(top5):
        print(f"\n  #{i+1}  score={e['score']:.2f}%  trial={e['trial']}")
        print(f"    nops={f['n_nops']}  fp_regs={f['n_distinct_fp_regs']}  "
              f"weight_pos={f['pos_weight_assign']}  "
              f"ability_walk_pos={f['pos_u32Ability_walk']}")
        if verbose:
            print("    Lines:")
            for l in e['regions']['group0']:
                print(f"      {l.strip()}")

    # ── 8. Validate (optional) ────────────────────────────────────────────────
    if validate_mode:
        print()
        validate(entries, feats, scores, root_dir)

    # ── 9. Cluster (optional) ─────────────────────────────────────────────────
    if cluster_mode:
        print()
        cluster_analysis(entries, feats, scores)

    # ── 10. Predict (optional) ────────────────────────────────────────────────
    if predict_mode:
        # --predict [func_name_or_path]
        # If next arg looks like a function name (no path sep, no .cpp), use it
        # as func_name and default the src path. Otherwise treat as src path.
        argv = sys.argv[:]
        pi = argv.index('--predict')
        default_src = os.path.join(
            root_dir,
            "src/Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp",
        )
        predict_src = default_src
        predict_func = 'setup'
        if pi + 1 < len(argv) and not argv[pi + 1].startswith('--'):
            arg = argv[pi + 1]
            if os.sep not in arg and '/' not in arg and not arg.endswith('.cpp'):
                # Looks like a bare function name, e.g. "Limit" or "updateFrame"
                predict_func = arg
            else:
                predict_src = arg
        print()
        predict(entries, feats, scores, predict_src, predict_func)


# ─── Rule scoring ─────────────────────────────────────────────────────────────

def rule_score(f: Dict) -> float:
    """
    Score an entry against the 7 discovered rules (0.0–1.0).
    Each rule contributes equally.  Returns the fraction satisfied.
    """
    score = 0.0
    n = 0

    # RULE 1: n_nops == 10
    n += 1
    if f['n_nops'] == 10:
        score += 1.0

    # RULE 2: fewer distinct FP regs (≤ 5 = good, ≥ 8 = bad)
    n += 1
    if f['n_distinct_fp_regs'] <= 5:
        score += 1.0
    elif f['n_distinct_fp_regs'] <= 7:
        score += 0.5

    # RULE 3: weight_assign position >= 20 (comes late)
    n += 1
    if f['pos_weight_assign'] >= 20:
        score += 1.0
    elif f['pos_weight_assign'] >= 15:
        score += 0.5

    # RULE 4: u32Ability_base position <= 20 (comes early)
    n += 1
    if 0 <= f['pos_u32Ability_base'] <= 20:
        score += 1.0
    elif 0 <= f['pos_u32Ability_base'] <= 25:
        score += 0.5

    # RULE 5: u32Ability_walk position >= 35 (comes late)
    n += 1
    if f['pos_u32Ability_walk'] >= 35:
        score += 1.0
    elif f['pos_u32Ability_walk'] >= 28:
        score += 0.5

    # RULE 6: mtc1_ratio low (prefer lwc1→mul.s over mtc1)
    n += 1
    if f['mtc1_ratio'] < 0.05:
        score += 1.0
    elif f['mtc1_ratio'] < 0.10:
        score += 0.5

    # RULE 7: n_lui >= 4 (more = better)
    n += 1
    if f['n_lui'] >= 4:
        score += 1.0
    elif f['n_lui'] >= 2:
        score += 0.5

    return score / n


# ─── Validate ─────────────────────────────────────────────────────────────────

def validate(entries, feats, scores, root_dir: str):
    print("=" * 64)
    print("V. RULE VALIDATION")
    print("=" * 64)

    # ── V1: Internal correlation between rule score and match score ────────────
    print("\nV1. Rule satisfaction vs actual match score (internal dataset)")
    rule_scores = [rule_score(f) for f in feats]
    r = pearson(rule_scores, scores)
    print(f"  Pearson r between rule_score and match_score: {r:+.3f}")

    # Bucket by rule_score
    buckets: Dict[float, List[float]] = collections.defaultdict(list)
    for rs, ms in zip(rule_scores, scores):
        key = round(rs * 7) / 7   # quantised to each rule increment
        buckets[key].append(ms)

    print(f"\n  {'rules_met/7':<12s}  {'count':>6s}  {'avg_match%':>11s}  {'max':>7s}")
    print(f"  {'-'*12}  {'------':>6s}  {'-----------':>11s}  {'-------':>7s}")
    for k in sorted(buckets):
        n_rules = round(k * 7)
        ms_list = buckets[k]
        print(f"  {n_rules}/7        {len(ms_list):>6d}  "
              f"{sum(ms_list)/len(ms_list):>10.2f}%  "
              f"{max(ms_list):>7.2f}%")

    # ── V2: Ground truth — matched functions ───────────────────────────────────
    print("\nV2. Ground truth: already-matched functions")
    print("    (Does source obey the same rules the permuter discovered?)")

    gt_sources = _find_ground_truth_sources(root_dir)
    if not gt_sources:
        print("  No matched source files found in ground_truth list.")
        return

    for label, src_path, symbol in gt_sources:
        if not os.path.exists(src_path):
            print(f"\n  [{label}]  source not found: {src_path}")
            continue

        with open(src_path, encoding='utf-8', errors='replace') as fh:
            src_lines = fh.readlines()

        # Extract PERM region (if any) or use full function body
        region_lines = _extract_region_or_body(src_lines, symbol)
        if not region_lines:
            print(f"\n  [{label}]  could not extract function body")
            continue

        f_gt = _features_from_lines(region_lines, instrs=None)
        print(f"\n  [{label}]  ({len(region_lines)} lines)")

        # Source positional rules — only show if the predicates found the lines
        pos_rules = [
            ('pos_weight_assign',   'weight_late',       lambda v: v >= 20),
            ('pos_u32Ability_base', 'ability_base_early', lambda v: 0 <= v <= 20),
            ('pos_u32Ability_walk', 'ability_walk_late',  lambda v: v >= 35),
        ]
        src_applicable = False
        for key, name, pred in pos_rules:
            pos = f_gt[key]
            if pos >= 0:
                src_applicable = True
                ok = pred(pos)
                print(f"    src {name}: pos={pos}  {_tick(ok)}")
        if not src_applicable:
            print("    (source predicates n/a for this function — "
                  "no PERM lines found)")

        # ASM validation — disassemble the compiled .o
        obj_path = _find_obj(root_dir, src_path)
        if not obj_path:
            print("    asm: .o not found (run ninja first)")
            continue
        instrs = _disassemble(obj_path, symbol, root_dir=root_dir)
        if not instrs:
            print(f"    asm: symbol not found in {obj_path}")
            continue
        mnems = [mnemonic(i) for i in instrs]
        n_nops = mnems.count('nop')
        n_lui = mnems.count('lui')
        n_mtc1 = mnems.count('mtc1')
        fp_regs = {
            reg for ins in instrs for reg in re.findall(r'\bf\d+\b', ins)
        }
        nops_ok = n_nops == 10
        lui_ok = n_lui >= 4
        mtc1_ok = n_mtc1 / max(len(instrs), 1) < 0.05
        fp_ok = len(fp_regs) <= 5
        print(f"    asm nops={n_nops}  {_tick(nops_ok)} (rule: ==10)")
        print(f"    asm lui={n_lui}    {_tick(lui_ok)} (rule: ≥4)")
        print(f"    asm mtc1={n_mtc1}  {_tick(mtc1_ok)} (rule: ratio<5%)")
        print(f"    asm fp_regs={len(fp_regs)} "
              f"{_tick(fp_ok)} (rule: ≤5)")

    print()


def _tick(ok: bool) -> str:
    return "OK" if ok else "XX"


def _find_ground_truth_sources(root_dir: str):
    """Return list of (label, src_path, mangled_symbol) for matched functions."""
    src_base = os.path.join(root_dir, "src")
    perf = os.path.join(
        src_base,
        "Develop/Projects/SR2/pgm/src/Object/Player/Performance.cpp",
    )
    return [
        ("Limit",       perf, "Limit__7clsPrfmFRQ27clsPrfm7stcData"),
        ("updateFrame", perf, "updateFrame__7clsPrfmFv"),
    ]


def _extract_region_or_body(src_lines: List[str], symbol: str) -> List[str]:
    """
    Try to extract PERM_BEGIN/END region named for this function.
    Fall back to finding the function body by brace matching.
    """
    bare = symbol.split('__')[0]   # e.g. "Limit"

    # First: try PERM_BEGIN block
    perm_start = -1
    perm_end = -1
    for i, line in enumerate(src_lines):
        if f'PERM_BEGIN' in line and bare in line:
            perm_start = i
        if perm_start >= 0 and 'PERM_END' in line:
            perm_end = i
            break
    if perm_start >= 0 and perm_end > perm_start:
        return src_lines[perm_start + 1:perm_end]

    # Fall back to brace-matched function body.
    # MWCC source uses: void clsPrfm::Limit(...) or void clsXxx::bare(
    func_start = -1
    for i, line in enumerate(src_lines):
        # Match "::<bare>(" pattern on a definition line (not declaration)
        if re.search(rf'::{re.escape(bare)}\s*\(', line):
            # Find the opening brace (may be on the same or next line)
            for j in range(i, min(i + 5, len(src_lines))):
                if '{' in src_lines[j]:
                    func_start = j
                    break
            if func_start >= 0:
                break

    if func_start < 0:
        return []

    # Collect body lines (until matching close brace at depth 0)
    depth = 0
    body = []
    for line in src_lines[func_start:]:
        depth += line.count('{') - line.count('}')
        body.append(line)
        if depth <= 0 and len(body) > 2:
            break
    return body


def _features_from_lines(lines: List[str], instrs) -> Dict:
    """Build feature dict from source lines (and optionally ASM)."""
    # Delegate to full extractor with a fake entry structure
    fake = {'regions': {'group0': lines}, 'instructions': instrs or []}
    return extract_features(fake)


def _find_obj(root_dir: str, src_path: str) -> Optional[str]:
    """Derive the compiled .o path from the source path."""
    # src/Develop/... → build/.../src/Develop/....o
    rel = os.path.relpath(src_path, os.path.join(root_dir, "src"))
    obj = os.path.join(root_dir, "build",
                       "SLUS-21642-PROTO-070901", "src",
                       rel.replace(".cpp", ".o").replace(".c", ".o"))
    return obj if os.path.exists(obj) else None


def _disassemble(
    obj_path: str, symbol: str, root_dir: str = ""
) -> Optional[List[str]]:
    """Run objdump on obj_path and extract instructions for symbol."""
    # If root_dir supplied use it; otherwise fall back to guessing from path
    if root_dir:
        build_dir = os.path.join(root_dir, "build")
    else:
        # Walk up until we find a 'build' dir (legacy fallback)
        build_dir = obj_path
        for _ in range(20):
            build_dir = os.path.dirname(build_dir)
            if os.path.basename(build_dir) == "build":
                break
    binutils = os.path.join(
        build_dir,
        "binutils",
        "mips-linux-gnu-objdump" + (".exe" if sys.platform == "win32" else ""),
    )
    if not os.path.exists(binutils):
        return None
    try:
        out = subprocess.check_output(
            [binutils, "-d", "--no-show-raw-insn", obj_path],
            stderr=subprocess.DEVNULL, text=True,
        )
    except Exception:
        return None

    # Precompute matching helpers for demangled → mangled lookup
    bare = symbol.split('::')[-1].split('(')[0]
    cls  = symbol.split('::')[0] if '::' in symbol else ''

    def _line_starts_sym(line: str) -> bool:
        if f"<{symbol}>:" in line:
            return True
        sym_part = re.search(r'<([^>]+)>:', line)
        if sym_part:
            mangled = sym_part.group(1)
            if mangled.startswith(bare + '__'):
                return True
            if cls and f'{bare}__{len(cls)}{cls}' in mangled:
                return True
        return False

    # Find symbol section
    found = False
    instrs = []
    for line in out.splitlines():
        if _line_starts_sym(line):
            found = True
            continue
        if found:
            if line.strip() == "" or (line.endswith(">:") and "<" in line):
                if instrs:
                    break
            m = re.match(r'\s+[0-9a-f]+:\s+(.+)', line)
            if m:
                instrs.append(m.group(1).strip())
    return instrs if instrs else None


# ─── Clustering ───────────────────────────────────────────────────────────────

def _instr_fingerprint(instrs: List[str]) -> tuple:
    """
    Reduce an instruction list to a tuple of (mnemonic, stripped_operands).
    Registers and immediates are normalised away so structurally identical
    sequences hash equal regardless of register allocation differences.
    """
    fp = []
    for raw in instrs:
        parts = raw.split('\t', 1)
        mn = parts[0].strip()
        # Keep only the mnemonic + operand count (strip actual values)
        ops = parts[1] if len(parts) > 1 else ''
        n_ops = ops.count(',') + (1 if ops.strip() else 0)
        fp.append((mn, n_ops))
    return tuple(fp)


def _instr_sequence(instrs: List[str], start: int, length: int = 6) -> tuple:
    """Extract a short mnemonic sequence starting at offset start."""
    window = instrs[start:start + length]
    return tuple(i.split('\t')[0].strip() for i in window)


def cluster_analysis(entries, feats, scores):
    print("=" * 64)
    print("C. CLUSTER ANALYSIS")
    print("=" * 64)

    # Only use entries with instructions
    with_instrs = [(e, f) for e, f in zip(entries, feats)
                   if e['instructions']]
    if not with_instrs:
        print("  No entries with instructions found.")
        return
    print(f"  Entries with instructions: {len(with_instrs)}\n")

    # ── C1: Instruction count distribution by score tier ─────────────────────
    print("C1. Instruction count by score tier")
    all_scores_cl = [e['score'] for e, _ in with_instrs]
    s_min_cl, s_max_cl = min(all_scores_cl), max(all_scores_cl)
    s_range_cl = s_max_cl - s_min_cl
    hi_thresh_cl = s_min_cl + s_range_cl * 0.80
    lo_thresh_cl = s_min_cl + s_range_cl * 0.40
    mid_thresh_cl = s_min_cl + s_range_cl * 0.60
    tiers = [
        (f"{hi_thresh_cl:.1f}%+", lambda s, h=hi_thresh_cl: s >= h),
        (f"{mid_thresh_cl:.1f}-{hi_thresh_cl:.1f}%", lambda s, m=mid_thresh_cl, h=hi_thresh_cl: m <= s < h),
        (f"{lo_thresh_cl:.1f}-{mid_thresh_cl:.1f}%", lambda s, l=lo_thresh_cl, m=mid_thresh_cl: l <= s < m),
        (f"<{lo_thresh_cl:.1f}%", lambda s, l=lo_thresh_cl: s < l),
    ]
    print(f"  {'tier':<10s}  {'count':>6s}  {'avg_instrs':>11s}  "
          f"{'avg_nops':>9s}  {'avg_lui':>8s}")
    for label, pred in tiers:
        grp = [(e, f) for e, f in with_instrs if pred(e['score'])]
        if not grp:
            continue
        avg_i = sum(len(e['instructions']) for e, _ in grp) / len(grp)
        avg_n = sum(f['n_nops'] for _, f in grp) / len(grp)
        avg_l = sum(f['n_lui'] for _, f in grp) / len(grp)
        print(f"  {label:<10s}  {len(grp):>6d}  {avg_i:>11.1f}  "
              f"{avg_n:>9.2f}  {avg_l:>8.2f}")
    print()

    # ── C2: Fingerprint clustering — how many distinct ASM shapes exist ───────
    print("C2. Distinct ASM fingerprints per score tier")
    for label, pred in tiers:
        grp = [(e, f) for e, f in with_instrs if pred(e['score'])]
        if not grp:
            continue
        fps = collections.Counter(
            _instr_fingerprint(e['instructions']) for e, _ in grp
        )
        print(f"  {label:<10s}  {len(fps):>4d} distinct shapes  "
              f"(top shape covers {fps.most_common(1)[0][1]} / {len(grp)})")
    print()

    # ── C3: Find instruction windows that differ between top and bottom tiers ──
    print(f"C3. Instruction windows unique to {hi_thresh_cl:.1f}%+ vs <{lo_thresh_cl:.1f}%")
    hi_entries = [e for e, _ in with_instrs if e['score'] >= hi_thresh_cl]
    lo_entries = [e for e, _ in with_instrs if e['score'] < lo_thresh_cl]
    if not hi_entries or not lo_entries:
        print("  Not enough data in both tiers.")
        return

    WINDOW = 4
    hi_windows: collections.Counter = collections.Counter()
    lo_windows: collections.Counter = collections.Counter()
    for e in hi_entries:
        instrs = e['instructions']
        for i in range(len(instrs) - WINDOW):
            hi_windows[_instr_sequence(instrs, i, WINDOW)] += 1
    for e in lo_entries:
        instrs = e['instructions']
        for i in range(len(instrs) - WINDOW):
            lo_windows[_instr_sequence(instrs, i, WINDOW)] += 1

    hi_total = len(hi_entries)
    lo_total = len(lo_entries)

    # Score each window: how much more common is it in hi vs lo?
    all_windows = set(hi_windows) | set(lo_windows)
    window_lift = []
    for w in all_windows:
        hi_rate = hi_windows[w] / hi_total
        lo_rate = lo_windows[w] / lo_total
        if hi_rate + lo_rate < 0.05:
            continue
        lift = hi_rate - lo_rate
        window_lift.append((w, lift, hi_rate, lo_rate))

    window_lift.sort(key=lambda x: -x[1])

    print(f"  Windows more common in {hi_thresh_cl:.1f}%+ (hi={hi_total}, lo={lo_total}):")
    print(f"  {'sequence':<40s}  {'hi_rate':>8s}  {'lo_rate':>8s}  "
          f"{'lift':>7s}")
    for w, lift, hr, lr in window_lift[:10]:
        seq = ' → '.join(w)
        print(f"  {seq:<40s}  {hr:>8.2f}  {lr:>8.2f}  {lift:>+7.3f}")

    print()
    print(f"  Windows more common in <{lo_thresh_cl:.1f}% (likely wrong patterns):")
    for w, lift, hr, lr in reversed(window_lift[-10:]):
        seq = ' → '.join(w)
        print(f"  {seq:<40s}  {hr:>8.2f}  {lr:>8.2f}  {lift:>+7.3f}")

    # ── C4: Exact instruction diff at the score boundary ──────────────────────
    print()
    print("C4. Per-position instruction agreement with target")
    print("    (which instruction positions are most often wrong?)")

    # Get the target instructions from the compiled .o
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    symbol = hi_entries[0]['symbol']
    # Derive .o path from the symbol's source unit stored in entries
    # Fall back to scanning build/ for a Performance.o
    obj_path = None
    for e in hi_entries[:1]:
        # entries don't store the unit, so search by known path
        candidate = os.path.join(
            root_dir, "build", "SLUS-21642-PROTO-070901", "src",
            "Develop/Projects/SR2/pgm/src/Object/Player/Performance.o",
        )
        if os.path.exists(candidate):
            obj_path = candidate
            break
    if not obj_path:
        print("  .o not found — run ninja first")
        return

    target_instrs = _disassemble(obj_path, symbol, root_dir=root_dir)
    if not target_instrs:
        print("  Could not disassemble target")
        return

    n = min(len(target_instrs), 60)   # first 60 positions

    # For each score tier, count how often position i matches target mnemonic
    def tier_agree(entries_grp, n_positions):
        agree = [0] * n_positions
        counts = [0] * n_positions
        for e in entries_grp:
            instrs = e['instructions']
            for i in range(min(n_positions, len(instrs))):
                mn_cand = instrs[i].split('\t')[0].strip()
                mn_tgt  = target_instrs[i].split('\t')[0].strip()
                counts[i] += 1
                if mn_cand == mn_tgt:
                    agree[i] += 1
        return [a / c if c else 0 for a, c in zip(agree, counts)]

    hi_agree = tier_agree(hi_entries, n)
    lo_agree = tier_agree(lo_entries, n)

    hi_label = f"{hi_thresh_cl:.0f}%+"
    lo_label = f"<{lo_thresh_cl:.0f}%"
    print(f"  {'pos':>4s}  {'target_mnem':<12s}  {hi_label:>6s}  "
          f"{lo_label:>7s}  {'diff':>6s}")
    print(f"  {'----':>4s}  {'------------':<12s}  {'------':>6s}  "
          f"{'-------':>7s}  {'------':>6s}")
    worst = []
    for i in range(n):
        mn = target_instrs[i].split('\t')[0].strip()
        diff = hi_agree[i] - lo_agree[i]
        worst.append((i, mn, hi_agree[i], lo_agree[i], diff))

    # Show positions with biggest disagreement between tiers
    worst.sort(key=lambda x: -abs(x[4]))
    for i, mn, ha, la, diff in worst[:15]:
        print(f"  {i*4:>4x}  {mn:<12s}  {ha:>6.2f}  {la:>7.2f}  {diff:>+6.3f}")
    print()


# ─── Predictor ────────────────────────────────────────────────────────────────

def _generic_src_features(lines: List[str]) -> Dict:
    """
    Extract function-agnostic source features from a list of body lines.
    Works on any function — no setup-specific predicates.
    """
    f: Dict = {}
    n = len(lines)
    f['n_lines'] = n

    # Store / load counts
    f['n_this_stores'] = sum(1 for l in lines if 'this->' in l and '=' in l
                             and not l.lstrip().startswith('//'))
    f['n_branches'] = sum(1 for l in lines
                          if re.search(r'\bif\b|\belse\b|\bswitch\b', l)
                          and not l.lstrip().startswith('//'))
    f['n_returns'] = sum(1 for l in lines if re.search(r'\breturn\b', l)
                         and not l.lstrip().startswith('//'))

    # Float temp patterns
    float_temps = {}  # var_name → line index of definition
    for i, l in enumerate(lines):
        if l.lstrip().startswith('//'):
            continue
        m = re.match(r'\s*float\s+(\w+)\s*=\s*[^;]+;', l)
        if m:
            float_temps[m.group(1)] = i
    f['n_float_temps'] = len(float_temps)

    # Gap between float temp definition and first use in a store
    gaps = []
    used_at: Dict[str, int] = {}
    for i, l in enumerate(lines):
        if l.lstrip().startswith('//'):
            continue
        for var, def_line in float_temps.items():
            if i > def_line and var in l and 'this->' in l and var not in used_at:
                used_at[var] = i
                gaps.append(i - def_line)
    f['n_temp_gaps'] = len(gaps)
    f['avg_temp_gap'] = sum(gaps) / len(gaps) if gaps else 0.0
    f['max_temp_gap'] = max(gaps) if gaps else 0

    # Direct stores: this->x = src->y  (no temp intermediary)
    f['n_direct_stores'] = sum(
        1 for l in lines
        if re.match(r'\s*this->\S+\s*=\s*\w+[\.\[]', l)
        and not l.lstrip().startswith('//')
        and '*' not in l
    )
    # Temp-mediated stores: this->x = rate * fVarN
    f['n_temp_stores'] = sum(
        1 for l in lines
        if re.match(r'\s*this->\S+\s*=\s*\w+\s*\*\s*\w+\s*;', l)
        and not l.lstrip().startswith('//')
    )

    # Position of first return (normalised by n_lines)
    first_ret = next(
        (i for i, l in enumerate(lines)
         if re.search(r'\breturn\b', l) and not l.lstrip().startswith('//')),
        -1
    )
    f['first_return_pos'] = first_ret
    f['first_return_frac'] = first_ret / n if first_ret >= 0 and n > 0 else -1.0

    # Unique field names accessed via this->
    fields = set(re.findall(r'this->(\w+)', ' '.join(lines)))
    f['n_unique_fields'] = len(fields)

    # Depth: avg nesting level of stores
    depth = 0
    depth_at_store = []
    for l in lines:
        if l.lstrip().startswith('//'):
            continue
        depth += l.count('{') - l.count('}')
        if 'this->' in l and '=' in l:
            depth_at_store.append(max(0, depth))
    f['avg_store_depth'] = (sum(depth_at_store) / len(depth_at_store)
                            if depth_at_store else 0.0)

    return f


def _ols_fit(X: List[List[float]], y: List[float]):
    """
    Ordinary least squares via normal equations: w = (X'X)^-1 X'y
    Adds a bias column. Returns (weights, bias).
    Pure Python, no external deps.
    """
    n = len(X)
    d = len(X[0])
    # Augment with bias column
    Xa = [row + [1.0] for row in X]

    # X'X  (d+1 x d+1)
    XtX = [[0.0] * (d + 1) for _ in range(d + 1)]
    for row in Xa:
        for i in range(d + 1):
            for j in range(d + 1):
                XtX[i][j] += row[i] * row[j]

    # Add small ridge to diagonal for numerical stability
    ridge = 1e-4
    for i in range(d + 1):
        XtX[i][i] += ridge

    # X'y  (d+1,)
    Xty = [0.0] * (d + 1)
    for row, yi in zip(Xa, y):
        for i in range(d + 1):
            Xty[i] += row[i] * yi

    # Solve via Gaussian elimination
    aug = [XtX[i][:] + [Xty[i]] for i in range(d + 1)]
    sz = d + 1
    for col in range(sz):
        # Pivot
        max_row = max(range(col, sz), key=lambda r: abs(aug[r][col]))
        aug[col], aug[max_row] = aug[max_row], aug[col]
        piv = aug[col][col]
        if abs(piv) < 1e-12:
            continue
        for r in range(sz):
            if r == col:
                continue
            factor = aug[r][col] / piv
            for c in range(sz + 1):
                aug[r][c] -= factor * aug[col][c]
        for c in range(sz + 1):
            aug[col][c] /= piv

    w = [aug[i][sz] for i in range(sz)]
    return w[:-1], w[-1]   # weights, bias


def _ols_predict(weights: List[float], bias: float, x: List[float]) -> float:
    return sum(wi * xi for wi, xi in zip(weights, x)) + bias


def _extract_func_body(src_lines: List[str], func_name: str) -> List[str]:
    """
    Find the active (non-commented) definition of func_name and return
    its body lines via brace matching.
    """
    func_start = -1
    pattern = re.compile(rf'::{re.escape(func_name)}\s*\(')
    for i, ln in enumerate(src_lines):
        if ln.lstrip().startswith('//'):
            continue
        if pattern.search(ln):
            for j in range(i, min(i + 5, len(src_lines))):
                if '{' in src_lines[j]:
                    func_start = j
                    break
            if func_start >= 0:
                break
    if func_start < 0:
        return []
    depth = 0
    body = []
    for ln in src_lines[func_start:]:
        depth += ln.count('{') - ln.count('}')
        body.append(ln)
        if depth <= 0 and len(body) > 2:
            break
    return body


def predict(entries, feats, scores, src_path: str, func_name: str = 'setup'):
    """
    Train a linear model on source-only generic features, filtered to
    entries for func_name, then predict the score for the current source.
    Works on any function — Limit, updateFrame, setup, etc.
    """
    print("=" * 64)
    print(f"P. SCORE PREDICTOR  —  {func_name}()")
    print("=" * 64)

    # Filter to entries matching this function.
    # Handles both mangled (setup__7clsPrfmF...) and demangled (clsPrfm::Limit)
    def matches(e):
        sym = e.get('symbol', '')
        bare = func_name.split('::')[-1]
        return (sym == func_name
                or sym.endswith('::' + bare)
                or (bare + '__') in sym
                or sym.startswith(bare + '__'))

    func_entries = [e for e in entries if matches(e)]
    if not func_entries:
        print(f"  No entries found for '{func_name}' in dataset.")
        print(f"  Run the permuter on {func_name} first to collect trials.")
        return
    print(f"  Found {len(func_entries)} trials for '{func_name}'  "
          f"(min={min(e['score'] for e in func_entries):.1f}%  "
          f"max={max(e['score'] for e in func_entries):.1f}%)\n")

    # Extract generic features from each entry's source region
    def entry_lines(e):
        r = e.get('regions', {})
        return r.get('group0') or next(iter(r.values()), []) if r else []

    train_pairs = []
    for e in func_entries:
        lines = entry_lines(e)
        if not lines:
            continue
        gf = _generic_src_features(lines)
        train_pairs.append((gf, e['score']))

    if len(train_pairs) < 10:
        print("  Not enough entries with source lines.")
        return

    feat_keys = sorted(train_pairs[0][0].keys())
    X = [[gf[k] for k in feat_keys] for gf, _ in train_pairs]
    y = [s for _, s in train_pairs]

    # Drop features with zero variance (useless for regression)
    keep = [k for k in feat_keys
            if len(set(row[feat_keys.index(k)] for row in X)) > 1]
    ki = [feat_keys.index(k) for k in keep]
    X = [[row[i] for i in ki] for row in X]

    weights, bias = _ols_fit(X, y)

    preds_train = [_ols_predict(weights, bias, x) for x in X]
    residuals = [abs(p - a) for p, a in zip(preds_train, y)]
    mae = sum(residuals) / len(residuals)
    r_fit = pearson(preds_train, y)
    print(f"  Model: {len(keep)} features  "
          f"MAE={mae:.2f}%  r={r_fit:+.3f}\n")

    # Top feature weights
    fw_sorted = sorted(zip(keep, weights), key=lambda x: -abs(x[1]))
    print(f"  {'feature':<26s}  {'weight':>8s}  direction")
    print(f"  {'-'*26}  {'-'*8}  {'-'*20}")
    for fname, fw in fw_sorted[:10]:
        direction = "↑ higher = better" if fw > 0 else "↓ lower  = better"
        bar = ('█' if fw > 0 else '░') * min(10, max(1, int(abs(fw) * 1.5)))
        print(f"  {fname:<26s}  {fw:>+8.3f}  {bar}  {direction}")
    print()

    # Load and extract from current source
    if not os.path.exists(src_path):
        print(f"  Source file not found: {src_path}")
        return

    with open(src_path, encoding='utf-8', errors='replace') as fh:
        src_lines = fh.readlines()

    body = _extract_func_body(src_lines, func_name)
    if not body:
        print(f"  Could not find active {func_name}() in {src_path}")
        return

    gf_query = _generic_src_features(body)
    x_query = [gf_query.get(k, 0.0) for k in keep]
    predicted = _ols_predict(weights, bias, x_query)
    predicted = max(0.0, min(100.0, predicted))

    print(f"  Source:          {src_path}")
    print(f"  Function:        {func_name}()")
    print(f"  Predicted score: {predicted:.2f}%\n")

    # Per-feature breakdown vs high-tier average
    hi_thresh = min(y) + (max(y) - min(y)) * 0.75
    hi_gfeats = [gf for gf, s in train_pairs if s >= hi_thresh]
    print(f"  Feature breakdown  (hi tier = top {100*(1-0.75):.0f}%,"
          f" n={len(hi_gfeats)}):")
    print(f"  {'feature':<26s}  {'yours':>7s}  {'hi avg':>7s}  status")
    print(f"  {'-'*26}  {'-'*7}  {'-'*7}  {'-'*22}")
    for fname, fw in fw_sorted[:12]:
        your_val = gf_query.get(fname, 0.0)
        hi_avg = (sum(g.get(fname, 0) for g in hi_gfeats) / len(hi_gfeats)
                  if hi_gfeats else 0.0)
        delta = your_val - hi_avg
        good = (fw > 0 and delta >= -1.0) or (fw < 0 and delta <= 1.0)
        status = "OK" if good else f"{'↑' if fw > 0 else '↓'} target~{hi_avg:.1f}"
        print(f"  {fname:<26s}  {your_val:>7.1f}  {hi_avg:>7.1f}  {status}")
    print()


# ─── Main ─────────────────────────────────────────────────────────────────────  (entry point moved to bottom)

if __name__ == "__main__":
    main()
