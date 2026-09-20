# Stash Rulesets

Stash (iOS/tvOS/macOS) 原生格式规则集,按 [stash.wiki](https://stash.wiki/) 规范生成。

## 特点

- **Stash 原生格式**: 规则集用 `behavior: domain` / `behavior: ipcidr`(Stash 官方推荐的优化格式,内存占用低、匹配快)
- **不生成 classical**: Stash 官方明确不推荐 classical(顺序匹配,性能差)
- **DOMAIN-KEYWORD 内联**: Stash domain 规则集不支持关键词语义,KEYWORD 规则放在主配置内联
- **自动更新**: GitHub Actions 每天 UTC 02:00 从上游拉取最新规则

## 目录结构

```
stash/
├── providers/          # 规则集文件 (behavior: domain / ipcidr)
│   ├── ChinaDomain_domain.yaml # 国内域名 (3672 条,微软误标条目已剔除)
│   ├── ChinaIp_ipcidr.yaml     # 国内 IP (7456 条)
│   └── ...
├── stash-full.yaml     # 完整配置模板 (导入 Stash 后填节点)
└── keywords.json       # DOMAIN-KEYWORD 清单 (主配置内联用)
```

## 使用方式

### 1. 完整配置

将 `stash-full.yaml` 作为 Stash 配置导入,在 `proxies:` 处填入你的节点。

### 2. 规则集 (CDN)

通过 jsDelivr CDN 引用单个规则集:

```yaml
rule-providers:
  google:
    type: http
    behavior: domain
    url: "https://fastly.jsdelivr.net/gh/ipevel/stash-rulesets@main/stash/providers/Google_domain.yaml"
    path: ./ruleset/google.yaml
    interval: 86400
```

## 规则集清单

| 规则集 | 类型 | 策略 | 说明 |
|---|---|---|---|
| OpenAI_domain / OpenAI_ipcidr | domain+ipcidr | Proxy | OpenAI |
| Claude_domain | domain | Proxy | Claude |
| GoogleGemini_domain | domain | Proxy | Gemini |
| ProxyMedia_domain / ProxyMedia_ipcidr | domain+ipcidr | Proxy | YouTube 等流媒体 |
| TikTok_domain | domain | Proxy | TikTok |
| Instagram_domain | domain | Proxy | Instagram |
| Netflix_domain | domain | Proxy | Netflix |
| Google_domain / Google_ipcidr | domain+ipcidr | Proxy | Google |
| GoogleFCM_domain / GoogleFCM_ipcidr | domain+ipcidr | Proxy | Google FCM |
| Apple_ipcidr | ipcidr | Proxy | Apple |
| GitHub_domain | domain | Proxy | GitHub |
| Bing_domain | domain | Proxy | Bing |
| OneDrive_domain | domain | Proxy | OneDrive |
| Microsoft_domain | domain | Proxy | Microsoft |
| ChinaDomain_domain | domain | DIRECT | 国内域名 |
| ChinaIp_ipcidr | ipcidr | DIRECT | 国内 IP (9647 条) |
| Telegram_domain / Telegram_ipcidr | domain+ipcidr | Proxy | Telegram |
| TelegramCIDR_ipcidr | ipcidr | Proxy | Telegram IP |
| ProxyGFWlist_domain | domain | Proxy | GFW 列表 |

广告拦截规则集（BanAD_domain / BanADCompany_ipcidr）已于 2026-09-20 移除，不再提供 REJECT 类规则集。
同时移除了 ChinaDomain 中被 blackmatrix7 误标为「国内直连」的微软条目
（office.com / outlook.com / office365.com / microsoftonline.com / windows.net / xboxlive.com 等），
否则这些服务在国内会被拉去直连而打不开。

## 生成

```bash
python3 scripts/generate_providers.py
```

## 上游

- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)
