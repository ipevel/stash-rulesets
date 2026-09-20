#!/usr/bin/env python3
"""
从 blackmatrix7/ios_rule_script + Loyalsoldier/clash-rules 拉取规则,
生成 Stash 原生格式的规则集 (stash/providers/*.yaml) + 主配置模板。

Stash 规则集格式 (https://stash.wiki/rules/rule-set):
  - behavior: domain   -> payload 是裸域名/通配符 (google.com / +.google.com / *.google.com)
  - behavior: ipcidr   -> payload 是裸 CIDR (1.2.3.0/24)
  - behavior: classical -> payload 是完整规则行 (不推荐, 顺序匹配性能差)

设计:
  1. 域名规则集 behavior: domain (内存优化)
  2. IP 规则集 behavior: ipcidr
  3. DOMAIN-KEYWORD 不进 provider (Stash domain 不支持关键词语义),
     单独提取到 KEYWORDS 清单, 主配置用 DOMAIN-KEYWORD 内联规则
  4. 策略在配置模板 rules 里指定, provider 文件只有裸条目
"""
import os
import re
import sys
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(BASE, "stash", "providers")
TEMPLATE = os.path.join(BASE, "stash", "stash-full.yaml")

BM7 = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{cat}/{file}"
LOYO = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/{file}"
UA = {"User-Agent": "Mozilla/5.0 (stash-rulesets-updater)"}

def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")

def parse_payload(text):
    items = []
    in_payload = False
    for line in text.splitlines():
        s = line.strip()
        if s == "payload:":
            in_payload = True
            continue
        if in_payload:
            if s.startswith("- "):
                item = s[2:].strip()
                if len(item) >= 2 and item[0] in "'\"" and item[-1] == item[0]:
                    item = item[1:-1]
                if item:
                    items.append(item)
    return items

def split_items(items):
    """拆分成 (domains, ipcidrs, keywords)。"""
    domains, ipcidrs, keywords = [], [], []
    for item in items:
        parts = item.split(",")
        head = parts[0].upper()
        val = parts[1].strip() if len(parts) > 1 else item
        if head == "DOMAIN":
            # 二次校验: DOMAIN,IP 形式 (上游异常) 归 ipcidr, 避免污染 domain provider
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", val) or re.match(r"^[0-9a-fA-F:]+/\d{1,3}$", val):
                ipcidrs.append(val)
            else:
                domains.append(val)
        elif head == "DOMAIN-SUFFIX":
            domains.append(f"+.{val}")
        elif head == "DOMAIN-WILDCARD":
            domains.append(val)
        elif head == "DOMAIN-KEYWORD":
            keywords.append(val)
        elif head == "IP-CIDR":
            ipcidrs.append(val)
        elif head == "IP-CIDR6":
            ipcidrs.append(val)
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", item):
            ipcidrs.append(item)
        elif re.match(r"^[0-9a-fA-F:]+/\d{1,3}$", item):
            ipcidrs.append(item)
        elif re.match(r"^[\w.-]+\.\w{2,}$", item):
            domains.append(item)
        elif item.startswith("+.") or item.startswith("*."):
            domains.append(item)
        # 其他 (PROCESS-NAME 等) 丢弃
    return domains, ipcidrs, keywords

# blackmatrix7 的 China_Domain 把一批微软域名标成「国内直连」，实际在国内不通，
# 会直接搞挂 Outlook / Office365 / Microsoft Store / Windows Update / Xbox。
# 这些应由 Microsoft_domain.yaml / OneDrive_domain.yaml（走代理）接管。
MS_DIRECT_DROP = {
    "download.microsoft.com",
    "+.dl.delivery.mp.microsoft.com",
    "+.hotmail.com",
    "+.microsoftonline.com",
    "+.office.com",
    "+.office.net",
    "+.office365.com",
    "+.outlook.com",
    "+.s-microsoft.com",
    "+.sharepoint.com",
    "+.update.microsoft.com",
    "+.windows.com",
    "+.windows.net",
    "+.windowsupdate.com",
    "+.windowsupdate.microsoft.com",
    "+.xbox.com",
    "+.xboxlive.com",
}


def drop_microsoft_direct(domains):
    """从国内直连列表里剔除微软条目（精确值匹配，不误伤 chinalive.com 等）。"""
    return [d for d in domains if d not in MS_DIRECT_DROP]


def write_provider(fname, entries):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, fname)
    with open(path, "w") as f:
        f.write(f"# {fname} - {len(entries)} rules\n")
        f.write("payload:\n")
        for e in entries:
            f.write(f"  - {e}\n")
    return len(entries)

# (url, 输出名, 策略, 是否生成 ipcidr 拆分)
SOURCES = [
    # --- AI ---
    (BM7.format(cat="OpenAI", file="OpenAI.yaml"), "OpenAI", "Proxy"),
    (BM7.format(cat="Claude", file="Claude.yaml"), "Claude", "Proxy"),
    (BM7.format(cat="Gemini", file="Gemini.yaml"), "GoogleGemini", "Proxy"),
    # --- 流媒体 & 社交 ---
    (BM7.format(cat="YouTube", file="YouTube.yaml"), "ProxyMedia", "Proxy"),
    (BM7.format(cat="TikTok", file="TikTok.yaml"), "TikTok", "Proxy"),
    (BM7.format(cat="Instagram", file="Instagram.yaml"), "Instagram", "Proxy"),
    (BM7.format(cat="Netflix", file="Netflix.yaml"), "Netflix", "Proxy"),
    # --- Google / Apple / GitHub / 微软 ---
    (BM7.format(cat="Google", file="Google.yaml"), "Google", "Proxy"),
    (BM7.format(cat="GoogleFCM", file="GoogleFCM.yaml"), "GoogleFCM", "Proxy"),
    (BM7.format(cat="Apple", file="Apple.yaml"), "Apple", "Proxy"),
    (BM7.format(cat="GitHub", file="GitHub.yaml"), "GitHub", "Proxy"),
    (BM7.format(cat="Bing", file="Bing.yaml"), "Bing", "Proxy"),
    (BM7.format(cat="OneDrive", file="OneDrive.yaml"), "OneDrive", "Proxy"),
    (BM7.format(cat="Microsoft", file="Microsoft.yaml"), "Microsoft", "Proxy"),
    # --- 国内 (不含游戏平台/哔哩哔哩/网易云音乐) ---
    (BM7.format(cat="China", file="China_Domain.yaml"), "ChinaDomain", "DIRECT"),
    (LOYO.format(file="cncidr.txt"), "ChinaIp", "DIRECT"),
    # --- Telegram / GFW ---
    (BM7.format(cat="Telegram", file="Telegram.yaml"), "Telegram", "Proxy"),
    (LOYO.format(file="gfw.txt"), "ProxyGFWlist", "Proxy"),
    (LOYO.format(file="telegramcidr.txt"), "TelegramCIDR", "Proxy"),
]

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    results = []
    total_d = total_i = total_k = 0
    all_keywords = {}  # provider -> [keywords]
    for url, out, policy in SOURCES:
        try:
            text = fetch(url)
            items = parse_payload(text)
            domains, ipcidrs, keywords = split_items(items)
            domains = list(dict.fromkeys(domains))
            ipcidrs = list(dict.fromkeys(ipcidrs))
            if out == "ChinaDomain":
                domains = drop_microsoft_direct(domains)
            if domains:
                total_d += write_provider(f"{out}_domain.yaml", domains)
            if ipcidrs:
                total_i += write_provider(f"{out}_ipcidr.yaml", ipcidrs)
            if keywords:
                all_keywords[out] = list(dict.fromkeys(keywords))
                total_k += len(keywords)
            results.append(f"OK   {out:20s} domain={len(domains):6d} ipcidr={len(ipcidrs):5d} kw={len(keywords):4d} ({policy})")
        except Exception as e:
            results.append(f"FAIL {out:20s} {url}: {e}")
    print("\n".join(results))
    print(f"\nTOTAL: domain={total_d} ipcidr={total_i} keyword={total_k}")
    # 保存 KEYWORD 清单供模板生成用
    with open(os.path.join(BASE, "stash", "keywords.json"), "w") as f:
        import json
        json.dump(all_keywords, f, ensure_ascii=False, indent=1)
    print("keywords.json 已保存")
    if any(r.startswith("FAIL") for r in results):
        sys.exit(1)

if __name__ == "__main__":
    main()
