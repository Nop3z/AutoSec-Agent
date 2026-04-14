# AutoSec-Agent
AutoSec-Agent

### 支持功能

- 生成网络拓扑图 
- TPS地址识别 
- 路由规则 
- 证书密钥识别 
- 加密算法识别 
- 27算法逆向
- 基带芯片 
- 座舱方案  
- 漏洞挖掘 
- 通信协议识别 
- 开源组件识别
- 固件解包
- 二进制文件元素导出
- 差量分析



### 项目架构

```
autosec-agent/
├── agent/                          # Agent 编排层
│   ├── __init__.py
│   ├── router.py                   # 输入路由 Agent：判断分析路径
│   ├── supervisor.py               # 主控 Supervisor：调度子工作流
│   └── workflows/                  # LangGraph 工作流定义
│       ├── __init__.py
│       ├── firmware_graph.py       # 固件分析子图
│       ├── network_graph.py        # 网络分析子图
│       ├── supply_chain_graph.py   # 开源组件/供应链子图
│       └── vuln_mining_graph.py    # 漏洞挖掘主图（聚合前面结果）
│
├── tools/                          # Tool 实现层（核心）
│   ├── __init__.py                 # 按类别暴露 tool 列表
│   ├── base.py                     # Tool 基类、公共异常、日志装饰器
│   │
│   ├── firmware/                   # 固件/二进制分析
│   │   ├── __init__.py
│   │   ├── crypto_detection.py     # 加密算法识别
│   │   ├── cert_key_extraction.py  # 证书密钥识别
│   │   ├── algo_reverse.py         # 27算法逆向
│   │   ├── chip_analysis.py        # 基带芯片识别
│   │   └── cockpit_analysis.py     # 座舱方案识别
│   │
│   ├── network/                    # 网络与通信分析
│   │   ├── __init__.py
│   │   ├── topology_mapper.py      # 生成网络拓扑图
│   │   ├── tps_resolver.py         # TPS地址识别
│   │   ├── route_extractor.py      # 路由规则提取
│   │   └── protocol_identifier.py  # 协议识别
│   │
│   ├── supply_chain/               # 供应链与依赖
│   │   ├── __init__.py
│   │   └── oss_detector.py         # 开源组件识别
│   │
│   └── vuln/                       # 漏洞挖掘专用（不直接分析原始输入，而是消费中间态）
│       ├── __init__.py
│       ├── pattern_matcher.py      # 基于规则/模式匹配
│       ├── heuristic_analyzer.py   # 启发式分析（硬编码密钥、危险函数等）
│       └── report_generator.py     # 结构化报告生成
│
├── core/                           # 核心基础设施
│   ├── __init__.py
│   ├── state.py                    # LangGraph StateSchema（所有字段必须在这里定义）
│   ├── models.py                   # Pydantic 模型：输入输出 Schema
│   ├── config.py                   # 配置管理（从 .env / yaml 加载）
│   └── persistence.py              # Checkpoint、SQLite、会话管理的封装
│
├── data/                           # 运行数据（不提交到 git）
│   ├── inputs/                     # 放置固件、镜像、抓包文件
│   ├── outputs/                    # 生成的报告、拓扑图、中间结果
│   └── checkpoints/                # SQLite checkpoint 数据库
│
├── config/                         # 配置文件
│   ├── tool_configs.yaml           # 各 tool 的阈值、规则路径
│   └── agent_prompts/              # 各 Agent 的系统提示词
│       ├── router_system.txt
│       ├── firmware_analyst.txt
│       └── vuln_miner.txt
│
├── tests/                          # 单元测试
│   ├── tools/
│   └── workflows/
│
└── pyproject.toml / README.md / AGENTS.md
```

