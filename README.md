# AdRulesUltra

[![Build and release AdRulesUltra rulesets](https://github.com/Lynricsy/AdRulesUltra/actions/workflows/build-release.yml/badge.svg)](https://github.com/Lynricsy/AdRulesUltra/actions/workflows/build-release.yml)
[![Latest release](https://img.shields.io/github/v/release/Lynricsy/AdRulesUltra?label=release&sort=semver&color=7c3aed)](https://github.com/Lynricsy/AdRulesUltra/releases/latest)
[![Release downloads](https://img.shields.io/github/downloads/Lynricsy/AdRulesUltra/total?label=downloads&color=0891b2)](https://github.com/Lynricsy/AdRulesUltra/releases)
![Ads domains](https://img.shields.io/badge/dynamic/json?label=ads%20domains&query=%24.badges.ads_domains&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=dc2626)
![Allow domains](https://img.shields.io/badge/dynamic/json?label=allow%20domains&query=%24.badges.allow_domains&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=16a34a)
![Malware domains](https://img.shields.io/badge/dynamic/json?label=malware%20domains&query=%24.badges.malware_domains&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=f97316)
![Total rules](https://img.shields.io/badge/dynamic/json?label=total%20rules&query=%24.badges.total_rules&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=2563eb)
![MRS size](https://img.shields.io/badge/dynamic/json?label=main%20MRS&query=%24.badges.ads_mrs_size&url=https%3A%2F%2Fgithub.com%2FLynricsy%2FAdRulesUltra%2Freleases%2Flatest%2Fdownload%2Fstats.json&color=9333ea)

AdRulesUltra 是一个独立的广告与恶意域名规则聚合项目。它定时拉取多个上游 DNS 规则源，合并、去重并转换为多种客户端可直接使用的规则集，包括 mihomo `.mrs`、sing-box `.srs`、Clash YAML、dnsmasq、SmartDNS、Surge 与 AdGuard 文本。

当前合并的上游：

- [AdGuard Home For Magisk Mod](https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod)
- [anti-AD](https://github.com/privacy-protection-tools/anti-AD)
- [dead-horse anti-AD whitelist](https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-for-clash.yaml)
- [Coolapk 1007 reward](https://raw.githubusercontent.com/lingeringsound/10007/main/reward)

## 产物

GitHub Actions 会每天拉取上游仓库，生成并发布这些 Release 资产。下列文件名中的 `{kind}` 为 `ads` / `allow` / `malware`：

| 文件 | 适用 | 说明 |
|---|---|---|
| `adrules_ultra_{kind}.mrs` | mihomo / Clash Meta | domain 二进制规则集 |
| `adrules_ultra_{kind}_ipcidr.mrs` | mihomo / Clash Meta | ipcidr 二进制规则集；非空时发布 |
| `adrules_ultra_{kind}_singbox.srs` | sing-box >= 1.10 | 二进制 rule-set；exact / suffix / subdomain / wildcard 分别映射 |
| `adrules_ultra_{kind}_singbox.json` | sing-box source | 编译 `.srs` 的源 JSON |
| `adrules_ultra_{kind}_clash.yaml` | Clash / mihomo text | `behavior: domain` payload |
| `adrules_ultra_{kind}_clash_ipcidr.yaml` | Clash / mihomo text | `behavior: ipcidr` payload；非空时发布 |
| `adrules_ultra_{kind}.txt` | mihomo text | domain text rule-provider，保留 `+.` / `.` 原语义 |
| `adrules_ultra_{kind}_ipcidr.txt` | mihomo text | ipcidr text rule-provider |
| `adrules_ultra_{kind}_domains.txt` | Pi-Hole 等 | 仅 exact + suffix 字面域名；不含 subdomain-only / wildcard |
| `adrules_ultra_{kind}_surge.txt` | Surge | `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-WILDCARD` / `IP-CIDR` |
| `adrules_ultra_{kind}_surge2.txt` | Surge DOMAIN-SET | exact 与 `.suffix`；不含 subdomain-only / wildcard |
| `adrules_ultra_{kind}_adguard.txt` | AdGuard / 兼容工具 | exact 保持 hosts 精确；suffix 用 `||`；subdomain-only 用正则 |
| `adrules_ultra_{kind}_easylist.txt` | AdGuard Home DNS | 与 adguard 文本同形 |
| `adrules_ultra_{ads,malware}_dnsmasq.conf` | dnsmasq | 仅 suffix 阻断；**不**为 allow 生成 |
| `adrules_ultra_{ads,malware}_smartdns.conf` | SmartDNS | 仅 suffix 阻断；**不**为 allow 生成 |
| `manifest.md` | - | 本次转换统计和上游提交 |
| `stats.json` | - | README 动态徽章读取的规则数量和 MRS 体积 |
| `SHA256SUMS` | - | Release 资产校验和 |

## 使用教程

### 1. 直接使用 Release

使用 `latest/download` 地址即可长期订阅最新产物。推荐把本项目规则放进 `sub-rules`，让 `@@` 例外规则使用 `PASS`：命中白名单时只退出 AdRulesUltra 子规则，后续仍会继续匹配你自己的代理、直连、地区分流规则。

```yaml
rule-providers:
  adrules_ultra_allow:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_allow.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_allow.mrs
    interval: 86400

  adrules_ultra_allow_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_allow_ipcidr.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_allow_ipcidr.mrs
    interval: 86400

  adrules_ultra_ads:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_ads.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_ads.mrs
    interval: 86400

  adrules_ultra_ads_ipcidr:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/adrules_ultra_ads_ipcidr.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_ads_ipcidr.mrs
    interval: 86400

  adrules_ultra_malware:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/adrules_ultra_malware.mrs
    url: https://github.com/Lynricsy/AdRulesUltra/releases/latest/download/adrules_ultra_malware.mrs
    interval: 86400

rules:
  - SUB-RULE,(NETWORK,tcp),adrules_ultra_filter
  - SUB-RULE,(NETWORK,udp),adrules_ultra_filter
  # 这里继续放你原本的代理、直连、地区分流规则。
  - MATCH,DIRECT

sub-rules:
  adrules_ultra_filter:
    - RULE-SET,adrules_ultra_allow,PASS
    - RULE-SET,adrules_ultra_allow_ipcidr,PASS,no-resolve
    - RULE-SET,adrules_ultra_ads,REJECT
    - RULE-SET,adrules_ultra_ads_ipcidr,REJECT,no-resolve
    - RULE-SET,adrules_ultra_malware,REJECT
    - MATCH,PASS
```

上游当前样本中 `adrules_ultra_malware_ipcidr.txt` 为空，GitHub Actions 只会在对应 text 非空时发布 `.mrs`。如果后续 Release 出现 `adrules_ultra_malware_ipcidr.mrs`，再按同样格式添加 `behavior: ipcidr` provider 即可。

不要把 `adrules_ultra_allow` 直接写成 `DIRECT`，否则命中 `@@` 例外的域名会强制直连，无法继续匹配你后面的代理规则。也不要把 `PASS` 白名单和 `REJECT` 拦截规则平铺在同一个 `rules` 列表里，否则白名单 `PASS` 后仍可能继续命中后面的广告拦截规则。

### 2. 手动下载校验

```bash
mkdir -p ruleset
cd ruleset

base=https://github.com/Lynricsy/AdRulesUltra/releases/latest/download
curl -fLO "$base/adrules_ultra_allow.mrs"
curl -fLO "$base/adrules_ultra_ads.mrs"
curl -fLO "$base/adrules_ultra_malware.mrs"
curl -fLO "$base/adrules_ultra_allow_ipcidr.mrs"
curl -fLO "$base/adrules_ultra_ads_ipcidr.mrs"
curl -fLO "$base/SHA256SUMS"

sed 's#  dist/#  #' SHA256SUMS | sha256sum -c --ignore-missing
```

`SHA256SUMS` 里会列出本次 Release 的全部资产；`--ignore-missing` 允许你只下载自己启用的规则集。

### 3. 自动更新来源

仓库自带 GitHub Actions：每天 UTC `20:23` 拉取四个上游，生成多格式文本，调用 mihomo 生成 `.mrs`、调用 sing-box 生成 `.srs`，再发布到 Release。需要立即刷新时，也可以在 Actions 页面手动运行 `Build and release AdRulesUltra rulesets`。

## 转换策略

转换器只保留能被 mihomo `domain` / `ipcidr` MRS 安全表达的 DNS 级规则：

- anti-AD 广告主列表直接读取 `anti-ad-clash.yaml` 的 `payload`
- dead-horse 的 `anti-ad-white-for-clash.yaml` 会合入 `adrules_ultra_allow`
- `||example.com^` 转为 `+.example.com`
- `@@||example.com^` 转入 `adrules_ultra_allow`
- `||203.0.113.1^` 转为 `203.0.113.1/32`
- `||216.239.35.0/24^` 转为 `216.239.35.0/24`
- `0.0.0.0 ads.example.com` 这类 hosts 规则转为 `ads.example.com`
- `||example.com/path.js^`、`||example.com:8443^` 这类带 URL 路径/端口的规则会被跳过，不再静默扩大为整域拦截
- `||ads*-normal*.example.com^` 这类可被 mihomo domain MRS 编译的 wildcard 会保留为 `+.ads*-normal*.example.com`
- `@@|blob:https://www.example.com` 这类仅有 host、无路径/端口的 URL 例外会转入 `adrules_ultra_allow`
- `$important` 会被接受，但 mihomo 只能靠规则顺序近似优先级
- 导出其他格式时会区分：
  - exact: `exact.example.com`
  - suffix: `+.example.com`（apex + 子域）
  - subdomain-only: `.example.com`（仅子域，不命中 apex）
  - wildcard: 含 `*` 的模式
- dnsmasq / SmartDNS 只接受明确的 suffix 阻断，exact 与 subdomain-only 不会被静默扩大
- allow 不会输出 dnsmasq / SmartDNS 阻断配置

默认策略是保守转换：DNS/domain 规则集无法完整表达的语义一律跳过，而不是把路径、端口或修饰符降级成整域命中。带 `@@` 的例外规则建议在 `sub-rules` 内用 `PASS` 近似“取消本项目拦截，然后回到主规则继续分流”。

这些规则会被跳过并写入统计：

- 正则规则，例如 `/example.*/`
- 带 URL 路径、query、fragment 或显式端口的规则（blocking / exception 均跳过）
- 纯路径规则或无法解析 host 的 URL 规则
- 只有 `$domain=` / `$app=` / `$client=` 这类条件、但没有拦截目标 host 的规则
- 无法在 DNS 层完整表达的修饰符规则，例如 `$script`、`$client`、`$dnstype`、`$dnsrewrite`
- 无法安全映射到 Clash wildcard 的复杂模式

## 本地运行

```bash
git clone --depth=1 https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod upstream-adguard
git clone --depth=1 https://github.com/privacy-protection-tools/anti-AD upstream-anti-ad
curl -fsSL https://raw.githubusercontent.com/privacy-protection-tools/dead-horse/master/anti-ad-white-for-clash.yaml -o upstream-anti-ad/anti-ad-white-for-clash.yaml
curl -fsSL https://raw.githubusercontent.com/lingeringsound/10007/main/reward -o upstream-coolapk-1007-reward.txt

uv run python -m scripts.build_rulesets \
  --adguard-source upstream-adguard \
  --anti-ad-source upstream-anti-ad \
  --coolapk-1007-reward-source upstream-coolapk-1007-reward.txt \
  --output dist \
  --adguard-commit "$(git -C upstream-adguard rev-parse HEAD)" \
  --anti-ad-commit "$(git -C upstream-anti-ad rev-parse HEAD)" \
  --dead-horse-commit "$(sha256sum upstream-anti-ad/anti-ad-white-for-clash.yaml | cut -d ' ' -f 1)" \
  --coolapk-1007-reward-commit "$(sha256sum upstream-coolapk-1007-reward.txt | cut -d ' ' -f 1)"
```

生成 `.mrs` 需要 mihomo，生成 `.srs` 需要 sing-box：

```bash
mihomo convert-ruleset domain text dist/adrules_ultra_ads.txt dist/adrules_ultra_ads.mrs
mihomo convert-ruleset domain text dist/adrules_ultra_allow.txt dist/adrules_ultra_allow.mrs
mihomo convert-ruleset domain text dist/adrules_ultra_malware.txt dist/adrules_ultra_malware.mrs

sing-box rule-set compile --output dist/adrules_ultra_ads_singbox.srs dist/adrules_ultra_ads_singbox.json
sing-box rule-set compile --output dist/adrules_ultra_allow_singbox.srs dist/adrules_ultra_allow_singbox.json
sing-box rule-set compile --output dist/adrules_ultra_malware_singbox.srs dist/adrules_ultra_malware_singbox.json
```
