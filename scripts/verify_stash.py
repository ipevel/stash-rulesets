#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stash 规则仓库完整性校验：
1) stash-full.yaml 里每个 rule-provider 的 behavior 是否与文件后缀(_domain/_ipcidr)匹配
2) provider 文件是否都存在
3) rules 里引用的 RULE-SET 名称是否都有定义
4) 是否残留广告拦截引用
"""
import os, re, sys
sys.stdout.reconfigure(encoding="utf-8")

BASE = r"E:\AI\Github\stash-rulesets"
PROV = os.path.join(BASE, "stash", "providers")
FULL = os.path.join(BASE, "stash", "stash-full.yaml")

txt = open(FULL, encoding="utf-8").read()
lines = txt.splitlines()

# ---- 解析 rule-providers ----
providers = []
in_block = False
cur = None
for ln in lines:
    if re.match(r"^rule-providers:", ln):
        in_block = True
        continue
    if in_block and re.match(r"^[a-zA-Z]", ln):
        break
    if not in_block or not ln.strip() or ln.lstrip().startswith("#"):
        continue
    indent = len(ln) - len(ln.lstrip())
    s = ln.strip()
    if indent == 2 and s.endswith(":"):
        cur = {"name": s[:-1], "behavior": None, "file": None}
        providers.append(cur)
    elif cur and indent > 2:
        if s.startswith("behavior:"):
            cur["behavior"] = s.split(":", 1)[1].strip()
        elif s.startswith("url:"):
            cur["file"] = os.path.basename(s.split(":", 1)[1].strip().strip('"'))

ok = True
print("=" * 74)
print("rule-providers 校验")
print("=" * 74)
for p in providers:
    name, beh, fn = p["name"], p["behavior"], p["file"]
    if not fn:
        continue
    exists = os.path.isfile(os.path.join(PROV, fn))
    suffix = "_domain" if fn.endswith("_domain.yaml") else ("_ipcidr" if fn.endswith("_ipcidr.yaml") else "?")
    exp = "domain" if suffix == "_domain" else ("ipcidr" if suffix == "_ipcidr" else "?")
    good = exists and beh == exp
    if not good:
        ok = False
    print("  %s %-16s behavior=%-8s 文件=%-28s %s" % (
        "OK " if good else "!!!", name, beh or "-", fn,
        "" if exists else " <-- 文件不存在"))

# ---- rules 里引用的 RULE-SET 是否都有定义 ----
defined = {p["name"] for p in providers}
used = set(re.findall(r"RULE-SET,([^,\s]+)", txt))
missing = used - defined
print()
print("=" * 74)
print("rules 引用校验")
print("=" * 74)
print("  已定义 provider:", len(defined))
print("  被引用的      :", len(used))
if missing:
    ok = False
    print("  !! 定义了但引用了不存在的 provider:", sorted(missing))
else:
    print("  OK 所有 RULE-SET 引用都有定义")

# ---- 广告残留 ----
ads = [ln.strip() for ln in lines if re.search(r"Ban[A-Za-z]*_|banad|BanAD|REJECT|🛑", ln)]
print()
print("=" * 74)
print("广告拦截残留检查")
print("=" * 74)
if ads:
    ok = False
    print("  !! 发现 %d 处:" % len(ads))
    for a in ads[:10]:
        print("     ", a[:100])
else:
    print("  OK 无残留")

# ---- provider 文件被引用情况 ----
files = {f for f in os.listdir(PROV) if f.endswith(".yaml")}
referenced = {p["file"] for p in providers if p["file"]}
orphan = files - referenced - {"keywords.json"}
print()
print("=" * 74)
print("孤儿文件检查")
print("=" * 74)
if orphan:
    print("  (未被引用，仅 CDN 可用):", sorted(orphan))
else:
    print("  OK 全部 provider 文件都被引用")

def strip_prefix(s):
    """去掉行首的 emoji / 变体选择符 / 空白，用于抓 '全球直连' vs '🎯 全球直连' 这类错配"""
    return re.sub(r"^[\U0001F000-\U0001FAFF️‍\s]+", "", s).strip()


# ---- 策略组成员名引用校验 ----
# 踩过的坑：成员写成 '全球直连' 而真实组名是 '🎯 全球直连'，mihomo 找不到该组会
# 顺延到列表里下一个真实节点，导致"改了默认出站却毫无效果"。
groups, members_of = [], {}
cur_grp = None
in_proxy_groups = False
for ln in lines:
    if ln.startswith("proxy-groups:"):
        in_proxy_groups = True
        continue
    if in_proxy_groups and ln and not ln.startswith(" ") and not ln.startswith("#"):
        break
    m = re.match(r"^  - name:\s*(.+)$", ln)
    if m and in_proxy_groups:
        cur_grp = m.group(1).strip().strip("'\"")
        groups.append(cur_grp)
        members_of[cur_grp] = []
        continue
    mm = re.match(r"^      - (.+)$", ln)
    if mm and cur_grp:
        members_of[cur_grp].append(mm.group(1).strip().strip("'\""))

BUILTIN = {"DIRECT", "REJECT", "GLOBAL", "PASS"}
gset = set(groups)

print()
print("=" * 74)
print("策略组成员名校验")
print("=" * 74)
print("  分组数: %d" % len(groups))
wrong = []
unknown = []
for g in groups:
    for mem in members_of[g]:
        if mem in gset or mem in BUILTIN:
            continue
        core = strip_prefix(mem)
        near = [x for x in gset if strip_prefix(x) == core]
        if near:
            wrong.append((g, mem, near[0]))
        else:
            unknown.append((g, mem))

if wrong:
    ok = False
    print("  !! 成员名与组名只差 emoji 前缀（引用必失败）:")
    for g, mem, real in wrong:
        print("     [%s] 引用「%s」，实际组名是「%s」" % (g, mem, real))
else:
    print("  OK 无 emoji 前缀错配")

if unknown:
    print("  (信息) 以下成员非本文件定义的组，由客户端节点列表提供，需人工确认:")
    for g, mem in unknown[:15]:
        print("     [%s] -> %s" % (g, mem))

print()
print("=" * 74)
print("结论:", "全部通过 ✓" if ok else "有问题 ✗")
sys.exit(0 if ok else 1)
