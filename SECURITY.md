# 安全政策

> 完整的使用条款、禁止行为清单、责任限制与免责声明见 [TERMS.md](TERMS.md)。

## 授权使用（重要）

CyberCensus 是**授权范围内的暴露面梳理工具**，不是攻击工具。

- 只允许对**你自有**或**已获得书面授权**的目标使用。
- 默认被动模式只查询第三方数据源；`--active` / `--cscan` / `--scan-asn` / `--verify` / `--probe-found` 会真实访问目标，使用前必须确认授权。
- 不得用于未经授权的扫描、入侵、数据窃取、拒绝服务或规避法律监管。
- 使用者需自行遵守所在国家/地区的法律法规、平台服务条款和客户合同。

## 报告安全问题

如果你发现的是 **CyberCensus 自身代码**的安全问题（例如命令注入、路径穿越、凭据泄露、更新器被劫持），请通过 GitHub 仓库的 **Security → Report a vulnerability** 私下报告，不要直接开公开 Issue。

请在报告中包含：

- 受影响版本 / 提交
- 复现步骤或最小 PoC
- 影响说明
- 你希望的处理方式（匿名/致谢等）

维护者会尽力在合理时间内确认和修复；在修复发布前请勿公开细节。

## 不在范围内

- 第三方平台（FOFA / Hunter / ZoomEye / Quake / Shodan / Censys 等）自身的安全问题，请向对应厂商报告。
- subfinder / httpx / wafw00f / nuclei 等外部工具的问题，请向各自上游项目报告。
- 因目标授权不清、超范围扫描、扫描频率过高造成的业务影响，不属于本项目的安全漏洞。

## 数据与凭据

- 平台 API Key 只保存在本机 `config.json` 或环境变量中，不会上传。
- `config.json`、`aliases.json`、`outputs/`、`cybercensus_out/`、`baseline.json` 已默认排除在 Git 之外。
- 提交 Issue / PR 时请勿附带真实客户数据、扫描结果、API Key 或内网地址；必要时请脱敏。
