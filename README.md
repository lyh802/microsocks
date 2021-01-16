# microsocks
tiny, portable SOCKS5 server with very moderate resource usage

1. 主要修复了IPV4/V6域名解析问题，优先获取与bind_addr类型一致的地址

2. 重构了逻辑，复用部分缓冲区，优化内存占用

3. 移植到OpenWrt 15.05.1 AR71XX平台，未完全测试，目前正常使用中
