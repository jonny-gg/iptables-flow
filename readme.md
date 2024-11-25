# 基于openstack计算浮动IP带宽
* 动态iptables规则生成
** 包含浮动IP,路由IP,虚拟机的IP 和对应的实例ID
1. iptables_manager.py 
* 计算真实外网访问的流量
1. iptables_flow.py