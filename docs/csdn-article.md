# CyberCensus：我写了个只认证据的暴露面测绘工具，输入单位名就能摸清它在公网上的资产

> 这是我自己开发的工具 **CyberCensus**，代码和发布包都在我的 GitHub 仓库里：
> **https://github.com/Zerdon-me/CyberCensus**
>
> 工具仅限**自有资产或已获书面授权**的目标使用。

CyberCensus 是我自己从零写的开源项目（Apache-2.0）：源码、使用文档、Windows 免安装包都在我的 GitHub 仓库里，可以直接下载、审计、二次开发。下面介绍它解决什么问题、有哪些功能、界面长什么样。

## 一、为什么我又造了一个轮子？

做安全服务的人大概都遇到过这种对话：

> "你们能不能帮我看看，我们单位在互联网上到底开了多少东西？"
>
> "我们官网是 xxx.gov.cn，其他的……不太清楚，可能是前几年外包做的。"

客户不知道自己有什么，这才是暴露面梳理最真实的样子。

现有工具不是不好用，而是各有门槛：

- **FOFA / Hunter / ZoomEye / Quake**：数据全，但要买会员、要会写语法，结果动辄几千条，真正属于客户的要一条条筛；
- **ARL 灯塔**：适合有域名、有 IP 段的单位，纯名称场景弱一些；
- **自己写脚本**：subfinder + httpx + nuclei 一套跑下来，能出资产，但"这条到底是不是客户的"仍然靠人猜。

所以我自己动手写了 **CyberCensus**（我的开源项目，仓库在 [GitHub](https://github.com/Zerdon-me/CyberCensus)）：输入一个**单位名称、域名或 IP**，它自动找资产，并且给每条资产标注**证据**，最后分成三份台账：

- ✅ **确认资产**：A 级证据 ≥1，或 B 级证据 ≥2
- 🟡 **疑似资产**：只有 1 条 B 级，或只有 C 级线索
- ⚪ **剔除（存疑）**：没有关联证据，并写明剔除原因

核心目标只有一句话：**误报不进确认清单。**

---

## 二、它到底特别在哪？

### 亮点 1：证据优先，不是"搜到就算"

很多工具的问题是"域名里带客户名字就算客户的"，结果把 CDN、云主机、同名的其他公司全卷进来。CyberCensus 给每条资产算证据：

| 级别 | 证据举例 |
|---|---|
| **A 强证据** | ICP 备案号主号一致、证书 `O=` 组织名一致、统一社会信用代码、政府网站标识码、公安备案号、RDAP 注册人、自有 ASN、LEI |
| **B 较强** | 统计/像素 ID（GA4/GTM/Meta）、Google/Bing/Facebook 域名验证令牌、页面联系邮箱/电话、页脚主办单位、页面互链、favicon 哈希、≥2 个平台交叉命中 |
| **C 弱线索** | 同 IP、平台 ASN/IP/关键词命中 |

判定规则：

```
确认 = A ≥ 1 或 B ≥ 2
疑似 = B = 1 或 C ≥ 1
剔除 = 无任何关联证据（并显示具体原因）
```

这样即使平台返回了几千条，进入"确认"的也只是证据够硬的那部分。

### 亮点 2：只给单位名称也能开工

没有域名、没有 IP、没有平台 Key，也能从名称开始：

1. 搜索引擎找官网候选 → 标题/证书互证
2. crt.sh 证书透明日志找子域
3. DNS / whois / IP 反查
4. 统计 ID、验证令牌、证书 SAN 兄弟域、MX/SPF 继续扩展

这条链路不依赖任何付费 API。当然，**有平台 Key 会更全**——工具支持 8 个平台，有 Key 就自动联动。

### 亮点 3：从发现到交付是一条完整的链

- 资产列表支持排序、搜索、多选、批量改判、复制 URL、导出 CSV
- 双击资产看完整证据，支持人工复核
- 7 种报告：HTML / PDF / Word / TXT / Markdown / CSV / JSON
- 资产关系图谱（HTML 可交互）
- 持续监控 `--watch`、基线对比、Webhook 告警
- Windows 解压双击即用，完整包自带 subfinder / httpx / wafw00f / nuclei 和官方模板

---

## 三、界面长什么样？

Windows 原生 GUI，不用记命令行。下面都是实际界面截图（尚未开始扫描的初始状态）。

**图 1：主界面**

![主界面](screenshots/01-main.png)

- 目标输入框：名称 / 域名 / IP / 网段，自动识别输入类型
- 四种模式卡片：被动 / 标准 / 复核 / 主动，点卡片切换，下方显示该模式会调用哪些引擎
- 进度条和剩余时间：开始后实时估算
- 三张统计卡片：确认 / 疑似 / 剔除，点一下就只看那一类，再点一次恢复全部
- 资产列表：全选、批量改判、复制 URL / 复制主机、导出选中 CSV、双击看证据
- 底部：一键生成报告、打开输出目录、查看网页报告 / Markdown 报告

**图 2：高级参数**

![高级参数](screenshots/02-advanced.png)

并发线程、平台翻页、常用端口、全端口 / C 段扩展、敏感路径探测、增强引擎开关、
Webhook 告警、APP 包分析、路径线索采集、ASN 扫描、持续监控等都在这里，
改完立即生效；主动相关选项都带"授权"提示。

**图 3：报告格式选择**

![报告格式](screenshots/03-report.png)

HTML / PDF / Word / TXT / Markdown / CSV / JSON 七种格式可多选；
HTML 带可交互的资产关系图谱，PDF 由 HTML 无头打印生成。

---

## 四、三分钟上手

### 方式一：下载免安装包（推荐）

到 Releases 下载：

- GitHub：https://github.com/Zerdon-me/CyberCensus/releases
- GitCode：https://gitcode.com/chao321654987/CyberCensus/releases

解压后双击 `CyberCensus.exe`，不需要安装 Python。

完整包包含：

```
CyberCensus.exe
tools\subfinder.exe
tools\httpx.exe
tools\wafw00f.exe
tools\nuclei.exe
nuclei-templates\
```

### 方式二：源码运行

```bash
pip install -r requirements.txt customtkinter
python asm_gui.pyw
```

### 命令行示例

```bash
# 只给名称
python cybercensus.py -n "某单位"

# 已知域名
python cybercensus.py -d example.com

# 对疑似资产做 HTTP 复核
python cybercensus.py -d example.com --verify

# 主动扫描（必须已获书面授权）
python cybercensus.py -d example.com --active --top 100

# 持续监控
python cybercensus.py -d example.com --watch 30
```

---

## 五、它和 FOFA / Hunter 是什么关系？

一句话：**不是替代，是互补。**

- FOFA / Hunter / ZoomEye / Quake / Shodan / Censys 是"全网资产库"，数据量是资本和带宽堆出来的，本地工具不可能复制；
- CyberCensus 是"归属判定 + 持续监控 + 交付层"：把平台当数据源接进来，再用备案、证书、RDAP、ASN、统计 ID、验证令牌、联系方式、互链等证据，判断哪些资产属于这个客户。

有平台 Key：覆盖接近平台本身，误报由本地证据链压下来。
没有 Key：靠公开源 + 搜索引擎 + 证书日志，覆盖面小一些，但零成本、零数据外发。

---

## 六、适合谁，不适合谁

**适合：**

- 做等保、攻防演练、暴露面梳理的安全服务商
- 政府 / 医院 / 学校 / 运营商等单位的内部安全团队
- 想从"单位名称"快速摸清资产范围，再人工核实的同学
- 需要给客户交付一份"能看懂、能复核"的资产台账的人

**不适合：**

- 想拿它当"一键日站"工具的人（它不做弱口令、不做验证码绕过、不做批量攻击）
- 期待不配置任何数据源就能达到 FOFA 全网覆盖的人
- 未经授权扫描非自有目标的人

---

## 七、开源与合规

- 许可证：**Apache-2.0**
- CyberCensus 是我个人开发并维护的项目，代码全部开源，可审计、可私有化部署、可二次开发
- 仓库里不含任何平台 Key、客户数据或扫描结果
- 仅限**自有资产或已获书面授权**的目标使用；主动扫描会真实访问目标，请先确认授权

项目地址：

- GitHub：https://github.com/Zerdon-me/CyberCensus
- GitCode：https://gitcode.com/chao321654987/CyberCensus

如果这个思路对你有用，欢迎 Star、提 Issue、提交 PR；也欢迎在评论区说说你遇到的"客户不知道自己有什么"的真实案例。

---

## 发布信息（CSDN 后台填写建议）

**标题：**

CyberCensus：我写了个只认证据的暴露面测绘工具，输入单位名就能摸清它在公网上的资产

**摘要：**

这是我自己的开源项目 CyberCensus（GitHub：Zerdon-me/CyberCensus）。输入单位名称/域名/IP，自动梳理公网暴露资产，用 ICP、证书 O=、RDAP、ASN、统计 ID 等 A/B/C 证据分级，输出确认/疑似/剔除三份台账，误报不进确认清单。支持 8 个测绘平台、Windows 一键运行、持续监控与资产图谱。

**标签：**

网络安全、信息收集、渗透测试、开源工具、攻击面管理、Python、Windows

**分类：**

安全 / 网络安全 / 安全工具

**图片上传：**

CSDN 编辑器不会读取仓库里的相对路径，正文粘贴后把下面 3 张图按顺序拖进编辑器，
替换掉对应的 `![...](screenshots/xx.png)`：

1. `docs/screenshots/01-main.png`
2. `docs/screenshots/02-advanced.png`
3. `docs/screenshots/03-report.png`

**封面：** 用 `docs/social-preview.png`（1280×640）。
