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
# polaris-rules 合并后的 AI 清单（ACL4SSR 的 AI/OpenAi/ClaudeAI/Gemini 四份合并去重），
# 覆盖 OpenAI / Claude / Gemini / Groq / Perplexity / Mistral / Meta AI / xAI / Cursor /
# JetBrains / GitHub·Microsoft Copilot 等，比本仓原本只拉 OpenAI/Claude/Gemini 三份更全。
POLARIS_AI = "https://raw.githubusercontent.com/ipevel/polaris-rules/main/dist/rules/ai.list"
UA = {"User-Agent": "Mozilla/5.0 (stash-rulesets-updater)"}

def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")

def parse_list(text):
    """提取纯文本规则列表（每行一条，无 payload: 包裹）。

    polaris-rules 的 dist/rules/*.list 就是这种格式：一行一条 Clash 规则行。
    """
    items = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        items.append(s)
    return items

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


# AI 服务普遍依赖的第三方基础设施（登录/支付/人机验证/统计/客服/证书）。
# 这些域名被 ACL4SSR 和 blackmatrix7 打进了 AI 清单，但它们服务的是**全网大量与 AI 无关的站点**
# （Intercom 挂在无数网站上、Cloudflare Turnstile、Sentry、Stripe 支付……）。
# 留在 AI 规则里会劫持非 AI 站点流量。2026-10-19 用户裁定：生成阶段统一剔除。
# 与 clash-rulesets 的同名名单保持一致。
AI_INFRA_DROP = {
    "auth0.com",
    "client-api.arkoselabs.com",
    "events.statsigapi.net",
    "featuregates.org",
    "identrust.com",
    "intercom.io",
    "intercomcdn.com",
    "challenges.cloudflare.com",
    "sentry.io",
    "stripe.com",
    # --- 2026-10-19 全量复查新发现（同样是服务全网非 AI 站的第三方 SaaS）---
    "algolia.net",                   # 站内搜索 SaaS
    "api.statsig.com",               # Statsig 埋点
    "browser-intake-datadoghq.com",  # Datadog 监控采集
    "static.cloudflareinsights.com", # Cloudflare 访问统计
    "usefathom.com",                 # 站点统计
    "livekit.cloud",                 # WebRTC 实时通信平台
    "launchdarkly.com",              # 功能开关
    "observeit.net",                 # 终端监控/审计
    "segment.io",                    # 用户数据管道
}

# 放错到 AI provider 的 Google 通用域名：不是 AI 服务，应由 🔍 Google 组接管
# （模板 Google 段有对应内联规则）。apis.google.com 是 Google 全系共用的
# API JS 加载网关，搜索页等都会拉它，留在 AI 段会让谷歌搜索被提前判成 AI 流量。
AI_MISPLACED_DROP = {
    "apis.google.com",
}

# 需要套用上面两个剔除名单的产出名（4 条 AI 产线）
AI_PROVIDERS = {"OpenAI", "Claude", "GoogleGemini", "AI"}


def drop_ai_infra(domains):
    """剔除 AI 清单里的第三方基础设施域名与放错的 Google 通用域名。

    Stash domain provider 的条目是裸域名或 '+.域名' 通配，两种都要比对到；
    父域匹配：名单写 livekit.cloud 可同时命中 chatgpt.livekit.cloud 等子域。
    """
    drop = AI_INFRA_DROP | AI_MISPLACED_DROP
    out = []
    for d in domains:
        v = d.lstrip("+.").strip().lower()
        if any(v == x or v.endswith("." + x) for x in drop):
            continue
        out.append(d)
    return out


def write_provider(fname, entries):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, fname)
    with open(path, "w") as f:
        f.write(f"# {fname} - {len(entries)} rules\n")
        f.write("payload:\n")
        for e in entries:
            f.write(f"  - {e}\n")
    return len(entries)

# (url, 输出名, 策略[, 源格式])  —— 源格式缺省为 payload，可选 "list"（纯文本规则列表）
SOURCES = [
    # --- AI ---
    (BM7.format(cat="OpenAI", file="OpenAI.yaml"), "OpenAI", "Proxy"),
    (BM7.format(cat="Claude", file="Claude.yaml"), "Claude", "Proxy"),
    (BM7.format(cat="Gemini", file="Gemini.yaml"), "GoogleGemini", "Proxy"),
    # 合并 AI 清单（来自 polaris-rules），作为 AI 平台的兜底：单条 RULE-SET 覆盖全部 AI 服务。
    (POLARIS_AI, "AI", "Proxy", "list"),
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
    # 国内 IPv6：从 blackmatrix7 ChinaIPs_IP 全量清单里只取 IPv6 段（fmt=ipcidr6）。
    # ChinaIp（cncidr.txt）只有 IPv4，GEOIP,CN 对 IPv6 的覆盖依赖内核 geoip 库，
    # 这里补一份显式 IPv6 清单作第二道保险，随日更刷新。
    (BM7.format(cat="ChinaIPs", file="ChinaIPs_IP.yaml"), "ChinaIpV6", "DIRECT", "ipcidr6"),
    # --- Telegram / GFW ---
    (BM7.format(cat="Telegram", file="Telegram.yaml"), "Telegram", "Proxy"),
    (LOYO.format(file="gfw.txt"), "ProxyGFWlist", "Proxy"),
    (LOYO.format(file="telegramcidr.txt"), "TelegramCIDR", "Proxy"),
]

# 合并源：把多个上游分类合并成一个 provider（去重），对应模板里的合并分组。
# 2026-10-19 用户要求社交/流媒体/开发者各自并成一个分组（与 clash-rulesets 同批整改）。
# 结构：(输出名, [(blackmatrix7 分类, 该分类文件名), ...])
MERGED_SOURCES = [
    ("Social", [
        ("Twitter",  "Twitter.yaml"),
        ("Facebook", "Facebook.yaml"),
        ("Whatsapp", "Whatsapp.yaml"),
        ("Discord",  "Discord.yaml"),
        ("Reddit",   "Reddit.yaml"),
    ]),
    ("Streaming", [
        ("Disney",     "Disney.yaml"),
        ("HBO",        "HBO.yaml"),
        ("PrimeVideo", "PrimeVideo.yaml"),
        ("Twitch",     "Twitch.yaml"),
        ("Spotify",    "Spotify.yaml"),
    ]),
    ("Dev", [
        ("GitLab", "GitLab.yaml"),
        ("Docker", "Docker.yaml"),
        ("Npmjs",  "Npmjs.yaml"),
        ("Python", "Python.yaml"),
    ]),
]

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    results = []
    total_d = total_i = total_k = 0
    all_keywords = {}  # provider -> [keywords]
    for src in SOURCES:
        url, out, policy = src[0], src[1], src[2]
        fmt = src[3] if len(src) > 3 else "payload"
        try:
            text = fetch(url)
            if fmt == "list":
                items = parse_list(text)
            else:
                items = parse_payload(text)
            domains, ipcidrs, keywords = split_items(items)
            domains = list(dict.fromkeys(domains))
            ipcidrs = list(dict.fromkeys(ipcidrs))
            if fmt == "ipcidr6":
                ipcidrs = [c for c in ipcidrs if ":" in c]
            if out == "ChinaDomain":
                domains = drop_microsoft_direct(domains)
            if out in AI_PROVIDERS:
                domains = drop_ai_infra(domains)
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

    # --- 合并源：多个上游分类合成一个 provider ---
    for out, cats in MERGED_SOURCES:
        try:
            domains, ipcidrs, keywords = [], [], []
            used = []
            for cat, fname in cats:
                url = BM7.format(cat=cat, file=fname)
                d, i, k = split_items(parse_payload(fetch(url)))
                used.append(f"{cat}({len(d)})")
                domains.extend(d)
                ipcidrs.extend(i)
                keywords.extend(k)
            domains = list(dict.fromkeys(domains))
            ipcidrs = list(dict.fromkeys(ipcidrs))
            if not domains and not ipcidrs:
                raise RuntimeError("empty rules")
            if domains:
                total_d += write_provider(f"{out}_domain.yaml", domains)
            if ipcidrs:
                total_i += write_provider(f"{out}_ipcidr.yaml", ipcidrs)
            if keywords:
                all_keywords[out] = list(dict.fromkeys(keywords))
                total_k += len(keywords)
            results.append(f"OK   {out:20s} domain={len(domains):6d} ipcidr={len(ipcidrs):5d} kw={len(keywords):4d} <- merged {' + '.join(used)}")
        except Exception as e:
            results.append(f"FAIL {out:20s} {e}")
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
