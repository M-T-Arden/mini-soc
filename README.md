# mini-soc-v2

A lightweight SOC rule detection engine and sample data generator project, suitable for demos and rapid prototyping.

## Features

- Parse JSON logs from multiple sources (`logs/*.json`) and normalize fields
- Detect alarms via configurable rules:
  - Brute force login behavior
  - Off-hours login
  - IP anomaly login
  - MFA suspicious behavior / user-agent detection
- Deduplicate/aggregate alerts by `rule/user/src_ip/type` and 15-min sliding window
- Print and output analysis report (console + JSON)
- Track metrics: raw vs deduped alerts, severity distribution, rule distribution, timeline, user/IP stats
- Support noisy, inconsistent, multi-source sample log generation (`generate_sample_logs.py`)

## File Structure

- `main.py`: entry point
- `config.py`: default paths and parameters
- `config/rules.yml`: rule configuration
- `core/parser.py`: log parser
- `core/engine.py`: rule engine + deduplication
- `core/dedup.py`: dedup logic
- `core/report.py`: incident report generation
- `core/metrics.py`: metrics collection
- `rules/*.py`: rule implementations
- `logs/*.json`: input log samples
- `output/*.json`: output reports
- `generate_sample_logs.py`: generate 50k noisy sample logs

## Quick Start

1. Create a virtual environment and install dependencies

```bash
pip install -r requirements.txt
```

2. Generate 50k sample logs

```bash
python generate_sample_logs.py --count 50000 --output logs/sample_50k.json
```

3. Run detection

```bash
python main.py --input logs/sample_50k.json
```

4. Enable metrics report

```bash
python main.py --input logs/sample_50k.json --metrics
```


---

## mini soc 项目

一个轻量级 SOC 规则检测引擎与样本数据生成项目，适用于演示和快速原型。

## 功能概述

- 读取 JSON 日志 (`logs/*.json`) 并解析为统一格式
- 基于可配置规则检测告警，实现：
  - 暴力破解登录（Brute Force）
  - 异常时段登录（Off Hours）
  - 异常 IP 变更（IP Anomaly）
  - MFA 可疑行为 / 代理 UA（MFA suspicious）
- 告警去重/聚合：按 `rule/user/src_ip/type` 分组，15分钟窗口内保留高危告警
- 输出分析报告（console + JSON）
- 生成指标：统计原始/去重告警数量、severity、规则分布、时间/用户/IP特征
- 支持高噪音、多源、格式不一致样本日志生成（`generate_sample_logs.py`）

## 文件结构

- `main.py`: 程序入口
- `config.py`: 默认路径和一些参数
- `config/rules.yml`: 规则配置
- `core/parser.py`: 日志解析
- `core/engine.py`: 规则执行 + 去重
- `core/dedup.py`: 去重逻辑
- `core/report.py`: 生成 incident 报告
- `core/metrics.py`: 指标统计
- `rules/*.py`: 各规则实现
- `logs/*.json`: 输入日志样本
- `output/*.json`: 报告输出
- `generate_sample_logs.py`: 生成50k模拟噪音日志

## Quick Start

1. 创建可执行环境并安装依赖（如有）

```bash
pip install -r requirements.txt
```

2. 生成 50k 样本日志

```bash
python generate_sample_logs.py --count 50000 --output logs/sample_50k.json
```

3. 运行检测

```bash
python main.py --input logs/sample_50k.json
```

4. 启用指标报告

```bash
python main.py --input logs/sample_50k.json --metrics
```

## 规则说明

- `brute_force`: `LOGIN_FAILED`/`AUTH_FAILURE` 同一用户同一IP，在窗口内失败次数超过阈值
- `off_hours`: `LOGIN_SUCCESS` 在定义的非工作时间内（默认22-05）
- `ip_anomaly`: 同一用户登录IP发生变化（仅 `LOGIN_SUCCESS`）
- `mfa_suspicious`: MFA失败次数阈值 + 可疑UA匹配

配置文件 `config/rules.yml` 可调参数：
- `weight`（打分权重）
- `threshold`, `window_seconds`（暴力破解）
- `mfa_threshold`, `suspicious_ua`
- `off_hours`, `whitelist`




