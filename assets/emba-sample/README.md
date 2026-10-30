# EMBA 产物格式夹具

这组文件按 EMBA master 的日志布局与字段顺序构造，用于离线验证
`scripts/adapter_emba.py` 的解析、稳定输出与失败关闭：

* `csv_logs/f50_base_aggregator.csv` — F50 汇总（版本、架构、CVE、仿真状态）
* `csv_logs/p99_prepare_analyzer.csv` — P99 文件类型与 ELF/PE32 信息
* `csv_logs/s09_firmware_base_version_check.csv` — S09 软件版本
* `csv_logs/l15_emulated_checks_nmap.csv` — L15 复制的服务行
* `csv_logs/l10_system_emulation.csv` — L10 系统仿真与开放端口
* `s115_usermode_emulator.txt` — S115 用户态仿真成功标记

字段名、列顺序和成功标记取自 EMBA 源码中的写入点（已按 HEAD `65b7870fb`
校准），包括 `write_csv_log()` 固定追加的 NA 填充列、L10 的
`IP address:` / `Network mode:` 展示前缀、F50 的仿真状态分号串，以及
`user_emulation_state` 实际存成功用户态仿真**计数**这一历史命名。
内容是为测试构造的合成数据，不是真实设备抓取。真实固件产物应在审计 run 中
替换本目录，并用 `--firmware` 让适配器独立核对固件哈希。仓库内不保存真实
固件与真实日志。
