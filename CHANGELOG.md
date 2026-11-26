# 更新日志

本项目遵循语义化版本（`主版本.次版本.修订号`）。

## [0.13.3] - 2026-11-26

### 修复

- CI 下载 ProjectDiscovery 引擎时带上 `GITHUB_TOKEN`，避免 Runner 共享 IP 触发 GitHub API 速率限制（403）导致 Linux/Windows 包构建失败

## [0.13.2] - 2026-11-26

### 修复

- Windows 32 位构建固定 `cryptography==44.0.2`（新版已不再提供 win32 wheel，导致 CI 从源码编译失败）

## [0.13.1] - 2026-11-26

### 发行包

- 新增 **Windows 32 位（x86）发行包** `CyberCensus-win32.zip`：
  - 32 位 Python + PyInstaller 构建的 `CyberCensus.exe`
  - 32 位 wafw00f
  - subfinder / httpx / nuclei 使用官方 `windows_386` 构建
  - 适合 Windows 8.1 / 10 / 11 的 32 位系统
- `packaging/pack_release.py` 支持 `--pkg-name` / `--sums-name`，可并行产出 win32 / win64 包
- README 增加“如何确认 32/64 位系统”和选择哪个包的说明

## [0.13.0] - 2026-11-26

### 合规与界面

- **首次启动条款确认**：GUI 首次运行弹出授权与 TERMS 确认，勾选同意后才能开始扫描（`.terms_accepted` 记录，可在安装目录删除后重新弹出）
- **关于 / 使用条款入口**：左侧配置区新增「关于 / 使用条款」，显示版本、许可证、TERMS、GitHub 地址
- **报告页脚**：HTML / PDF / Word / TXT / Markdown 报告统一追加授权声明、项目链接、Apache-2.0 与版本号
- 新增英文版 **TERMS.en.md**，README / README.en / 发行包同步

## [0.12.0] - 2026-11-26

### 新增

- **端口扫描预设**：`--top 100` / `1000` / `10000`，按 nmap-services 频率排序（10000 档约 8400 个）
- **端口字典文件**：`--ports-file FILE`，每行/逗号/空格分隔，支持 `8000-8100` 范围和 `#` 注释
- 端口优先级：全端口 > 端口字典 > 自定义 `--ports` > `--top` > 内置常见表
- GUI 高级参数同步加入：top 100 / 1000 / 10000 下拉、端口字典文件选择、原有自定义端口
- 新增 `port_presets.py`（自动生成）与 `tests/test_ports.py`

## [0.11.2] - 2026-11-26

### 界面

- 新增 **GUI 定时巡航面板**：
  - 选择/查看 `tasks.json`，任务列表显示周期、上次/下次运行时间、状态
  - **启动后台巡航 / 停止**，后台使用无窗口进程运行，日志写入 `cybercensus_cruise.log`
  - **立即执行一次**（只跑到期任务）
  - **+ 当前目标**：把当前目标、模式、输出目录、范围文件、保留轮数直接生成一条巡航任务，不需要手写 JSON
- exe / pyw 支持 `--tasks` 等命令行模式，供 GUI 后台巡航调用
- 命令行与 GUI 的 scope / keep / tasks 功能保持同步

## [0.11.1] - 2026-11-26

### 界面

- 高级参数新增 **报告保留轮数**（对应 `--keep`），0=不清理，长期使用建议 20~50
- 范围文件、只看范围内/相似资产、报告保留均可在 GUI 里完成，不需要命令行

## [0.11.0] - 2026-11-26

### 新增

- **资产范围过滤**：用户提供 URL/域名/IP 清单，把结果标注为 **范围内 / 相似 / 无关**
  - `--scope URL`（可多次）、`--scope-file FILE`（每行一个，`#` 注释）
  - `--only-scope` 只保留范围内/相似资产，无关项不进入表格和报告
  - 范围内 = 同域或子域；相似 = 同一可注册域或同 IP；其余为无关
  - 标注写入 CSV `scope` 列、JSON `asset.scope`、MD/HTML 报告「范围」列
  - 图形界面「高级参数」新增范围文件选择和“只看范围内/相似”开关
- 新增 `tests/test_scope.py`（URL 解析、可注册域、分类、范围文件）

## [0.10.1] - 2026-11-26

### 新增

- **报告保留策略 `--keep N`**：每轮结束后只保留最近 N 轮报告（按时间戳分组，所有格式一起清理），适合定时巡航长期运行
  - `0`（默认）表示不清理
  - 只删除 `cybercensus_<时间戳>.*` 报告文件，`baseline.json`、任务状态和历史记录不受影响
  - 示例任务文件已默认加 `--keep 30`

## [0.10.0] - 2026-11-26

### 新增

- **定时巡航（ARL 式多目标任务）**：`--tasks tasks.json` 按 `30m / 6h / 1d / 7d` 周期自动巡检多个目标
  - `--tasks-once` 只跑本轮到期任务，方便接 cron / Windows 计划任务
  - `--tasks-status` 查看上次/下次运行时间与任务状态
  - 每个任务独立输出目录，自动复用 `baseline.json` 做增量对比和 Webhook 告警
  - 任务状态写入 `<tasks.json>.state.json`，执行历史追加到 `<tasks.json>.history.jsonl`
  - 含主动扫描参数的任务必须显式 `"authorized": true`，否则跳过
- 新增 `examples/tasks.example.json` 示例任务文件
- 新增 `tests/test_schedule.py`（周期解析、任务加载、参数拆分、主动参数识别）

## [0.9.1] - 2026-11-25

### 新增

- **Linux x86_64 命令行发行包**：`CyberCensus-linux-x86_64.tar.gz`，内置 Linux 版 subfinder / httpx / nuclei 和官方模板，附 `install.sh`
- 界面版本号改为读取 `cybercensus.__version__`

### 文档

- README 增加 Linux 下载、安装与运行说明
- README 末尾新增免责声明
- CSDN 宣传稿标题带上项目名，并标明作者与 GitHub 仓库

## [0.9.0] - 2026-11-25

首个公开开源预览版。

### 核心

- 单位名称 / 域名 / IP / CIDR → 互联网暴露面台账
- A/B/C 证据分级：确认（A≥1 或 B≥2）/ 疑似 / 剔除（含剔除原因）
- 备案号主号比较、证书 O=、统一社会信用代码、政府网站标识码、公安备案
- 非备案归属证据：联系邮箱/电话、页脚单位、互链、统计 ID、验证令牌、RDAP、自有 ASN、LEI/VAT/DUNS

### 数据源

- 本地被动源：搜索引擎官网自举、crt.sh、RapidDNS、HackerTarget、OTX、urlscan、Wayback、Shodan InternetDB、App Store
- 平台联动（可选 Key）：FOFA、0.zone、Hunter、DayDayMap、ZoomEye、360 Quake、Shodan、Censys
- 归属扩展：统计/像素 ID、Google/Bing/Facebook 验证令牌、证书 SAN 兄弟域、MX/SPF 域名

### 主动能力（需书面授权）

- 端口扫描、Web 指纹、敏感路径、路径/接口线索、ASN 网段扩展
- 外部引擎：subfinder / httpx / wafw00f / nuclei（随完整包分发，可在线更新）

### 界面与报告

- CustomTkinter 深色界面；四种模式；能力矩阵；本机引擎状态
- 进度条百分比 + 阶段 + 预计剩余时间
- 资产表排序、搜索、多选、全选、批量改判、复制 URL/主机、导出选中 CSV
- 报告导出：HTML / PDF / Word / TXT / Markdown / CSV / JSON
- 资产关系图谱（HTML 可交互 canvas）
- 持续监控（`--watch`）+ 基线对比 + Webhook

### 许可

- 以 **Apache-2.0** 开源（含专利授权）；商业服务边界见 `COMMERCIAL.md`

### 工程

- 255 项离线单元测试
- GitHub Actions：测试 + Windows exe/完整包构建
- 增强引擎在线检查/更新（GitHub Release + 镜像回退 + 版本校验回滚）
