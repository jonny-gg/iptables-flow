#!/usr/local/iptables/venv/bin/python
# -*- coding: utf-8 -*-
import openstack
import subprocess
import logging
import sys
import re
import os
from typing import List, Dict, Set, Tuple
from collections import namedtuple

# 加载OpenStack环境变量和证书
def load_openstack_env():
    """加载OpenStack环境变量和证书"""
    try:
        # 执行source命令并获取环境变量
        cmd = ['bash', '-c', 'source /usr/local/iptables/admin-openrc.sh && env']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        for line in proc.stdout:
            line = line.decode().strip()
            if line.startswith('OS_'):
                key, value = line.split('=', 1)
                os.environ[key] = value
                logger.info(f"Loaded env: {key}={value}")

        # 设置证书
        os.environ['OS_CACERT'] = '/usr/local/iptables/external.crt'
        logger.info(f"Set OS_CACERT to {os.environ['OS_CACERT']}")

    except Exception as e:
        logger.error(f"Failed to load OpenStack environment: {str(e)}")
        raise


# OpenStack配置
def get_openstack_config():
    """获取OpenStack配置"""
    # 确保先加载环境变量
    load_openstack_env()

    config = {
        'auth_type': 'password',
        'auth_url': os.environ.get('OS_AUTH_URL'),
        'username': os.environ.get('OS_USERNAME'),
        'password': os.environ.get('OS_PASSWORD'),
        'project_name': os.environ.get('OS_PROJECT_NAME'),
        'project_domain_name': os.environ.get('OS_PROJECT_DOMAIN_NAME', 'default'),
        'user_domain_name': os.environ.get('OS_USER_DOMAIN_NAME', 'default'),
        'region_name': os.environ.get('OS_REGION_NAME', 'RegionOne'),
        'cacert': os.environ.get('OS_CACERT'),
        'verify': True
    }

    # 验证必要的配置是否存在
    required_keys = ['auth_url', 'username', 'password', 'project_name']
    missing_keys = [key for key in required_keys if not config[key]]

    if missing_keys:
        raise ValueError(f"Missing required OpenStack configurations: {missing_keys}")

    logger.info("OpenStack configuration loaded successfully")
    return config

# 配置日志
os.makedirs('/logs/iptables', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/iptables/iptables_manager.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 使用namedtuple定义数据结构
RouterInfo = namedtuple('RouterInfo', ['router_id', 'gateway_ip', 'floating_ips', 'instance_ips'])
InstanceInfo = namedtuple('InstanceInfo', ['instance_id', 'fixed_ip', 'floating_ip'])

class IPTablesManager:
    def __init__(self):
        """初始化IPTables管理器，建立OpenStack连接"""
        try:
            # 获取OpenStack配置
            self.config = get_openstack_config()
            logger.info(f"OpenStack Config: {self.config}")

            # 忽略SSL警告
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            self.conn = openstack.connect(**self.config)
            logger.info("Successfully connected to OpenStack")

        except Exception as e:
            logger.error(f"Failed to connect to OpenStack: {str(e)}")
            import traceback
            logger.error(f"Detailed error: {traceback.format_exc()}")
            raise

    def init_iptables_in_namespace(self, namespace):
        """在命名空间中初始化iptables必要的链和ipset"""
        try:
            # 检查并创建 subnet1 ipset
            ipset_found = 0
            stdout, _ = self._run_cmd_in_namespace(namespace, "/usr/sbin/ipset save")
            for line in stdout.split('\n'):
                if 'subnet1 hash:ip' in line:
                    ipset_found = 1
                    break;
            if not ipset_found:
                logger.info(f"Creating ipset subnet1 in namespace {namespace}")
                self._run_cmd_in_namespace(namespace, "/usr/sbin/ipset create subnet1 hash:ip")

            # 检查 mangle 表中是否存在 traffic_chain
            chain_found = 0
            stdout, _ = self._run_cmd_in_namespace(namespace, "/usr/local/iptables/iptables-save -t mangle | grep ^:")
            for line in stdout.split('\n'):
                if ':traffic_chain' in line:
                    chain_found = 1
                    break

            if not chain_found:
                # 创建 traffic_chain
                logger.info(f"Creating traffic_chain in namespace {namespace}")
                self._run_cmd_in_namespace(namespace, "/usr/local/iptables/iptables -t mangle -N traffic_chain")

            logger.info(f"Initialized iptables in namespace {namespace}")
        except Exception as e:
            logger.error(f"Failed to initialize iptables in namespace {namespace}: {str(e)}")
            raise

    def _safe_delete_rule(self, namespace: str, rule: str):
        """
        安全地删除iptables规则，修复了管道命令执行问题

        Args:
            namespace: 网络命名空间名称
            rule: 要删除的规则
        """
        # 脚本下发的规则都是有comment描述的
        try:
            sl = rule.split()
            idx = sl.index('--comment')
            if len(sl) < idx + 1:
                raise

            comment = sl[idx + 1]
        except:
            logger.warning(f"Unexpected rule, skipping: {rule}")
            return

        try:
            # 使用bash -c来正确执行管道命令
            check_cmd = f"bash -c '/usr/sbin/ip netns exec {namespace} /usr/local/iptables/iptables-save -t mangle | grep {comment}'"
            try:
                subprocess.check_output(check_cmd, shell=True, universal_newlines=True)
                # 如果规则存在，则删除它
                self._run_cmd_in_namespace(namespace, f"/usr/local/iptables/iptables -t mangle {rule}")
                logger.info(f"Successfully removed rule in namespace {namespace}: {rule}")
            except subprocess.CalledProcessError:
                # grep 没有找到匹配项，意味着规则不存在
                logger.info(f"Rule not found in namespace {namespace}, skipping: {rule}")
        except Exception as e:
            logger.warning(f"Error while trying to delete rule in namespace {namespace}: {rule}")
            logger.warning(f"Error details: {str(e)}")
    def _run_cmd_in_namespace(self, namespace, cmd):
        """在指定的网络命名空间中执行命令并返回结果"""
        try:
            # 添加错误输出到日志
            namespace_cmd = f"/usr/sbin/ip netns exec {namespace} {cmd}"
            process = subprocess.Popen(
                namespace_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                if 'No chain/target/match by that name' in stderr:
                    # 特殊处理链不存在的情况
                    logger.warning(f"Chain not found in namespace {namespace}, may need to initialize")
                    raise subprocess.CalledProcessError(
                        process.returncode,
                        namespace_cmd,
                        stdout,
                        stderr
                    )
                else:
                    logger.error(f"Command failed: {namespace_cmd}")
                    logger.error(f"Error output: {stderr}")
                    raise subprocess.CalledProcessError(
                        process.returncode,
                        namespace_cmd,
                        stdout,
                        stderr
                    )

            if stderr:
                logger.warning(f"Command warning: {stderr}")

            return stdout, stderr

        except Exception as e:
            logger.error(f"Command execution failed in namespace {namespace}: {cmd}")
            logger.error(f"Error: {str(e)}")
            raise

    def _run_cmd(self, cmd):
        """执行shell命令并返回结果"""
        try:
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)
            return stdout, stderr
        except Exception as e:
            logger.error(f"Command execution failed: {cmd}")
            logger.error(f"Error: {str(e)}")
            raise

    def get_router_namespaces(self):
        """获取所有qrouter网络命名空间"""
        try:
            stdout, _ = self._run_cmd("/usr/sbin/ip netns list")
            namespaces = []
            for line in stdout.splitlines():
                if 'qrouter-' in line:
                    namespace = line.split()[0]
                    namespaces.append(namespace)
            logger.info(f"Found {len(namespaces)} router namespaces")
            return namespaces
        except Exception as e:
            logger.error(f"Failed to get router namespaces: {str(e)}")
            raise
    def get_router_infos(self):
        """获取路由器信息列表"""
        router_infos = []
        try:
            # 获取所有路由器
            routers = list(self.conn.network.routers())
            logger.info(f"Found {len(routers)} routers")

            for router in routers:
                # 获取路由器的网关信息
                gateway_info = getattr(router, 'external_gateway_info', {}) or {}
                if not gateway_info:
                    continue

                external_fixed_ips = gateway_info.get('external_fixed_ips', [{}])
                if not external_fixed_ips:
                    continue

                gateway_ip = external_fixed_ips[0].get('ip_address')
                if not gateway_ip:
                    continue

                # 获取路由器关联的端口
                ports = list(self.conn.network.ports(device_id=router.id))
                floating_ips = []

                # 获取每个端口上的浮动IP
                for port in ports:
                    fixed_ips = getattr(port, 'fixed_ips', [])
                    for fixed_ip in fixed_ips:
                        # 查找与该固定IP关联的浮动IP
                        fips = list(self.conn.network.ips(fixed_ip_address=fixed_ip['ip_address']))
                        floating_ips.extend(fip.floating_ip_address for fip in fips)

                # 获取所有连接子网下所有的虚拟机端口
                instance_ips = []

                for rp in ports:
                    rp_subnets = [rpf['subnet_id'] for rpf in rp['fixed_ips']]
                    all_ports = list(self.conn.network.ports(network_id=rp['network_id']))
                    for p in [p for p in all_ports if p['device_owner'] == 'compute:nova']:
                        for f in p['fixed_ips']:
                            if f['subnet_id'] in rp_subnets:
                                instance_ips.append(f['ip_address'])

                router_infos.append(RouterInfo(
                    router_id=router.id,
                    gateway_ip=gateway_ip,
                    floating_ips=floating_ips,
                    instance_ips=instance_ips
                ))

            logger.info(f"Processed {len(router_infos)} routers with gateway IPs")
            return router_infos

        except Exception as e:
            logger.error(f"Failed to get router information: {str(e)}")
            raise
    def get_instance_infos(self):
        """获取实例信息列表"""
        instance_infos = []
        try:
            # 获取所有服务器实例
            servers = list(self.conn.compute.servers(all_projects=True))
            logger.info(f"Found {len(servers)} instances")

            for server in servers:
                # 获取实例的详细信息
                server_detail = self.conn.compute.get_server(server.id)
                addresses = getattr(server_detail, 'addresses', {}) or {}

                # 处理每个网络接口
                for network_name, address_list in addresses.items():
                    fixed_ips = []
                    floating_ips = []

                    for addr in address_list:
                        if addr.get('OS-EXT-IPS:type') == 'fixed':
                            fixed_ips.append(addr.get('addr'))
                        elif addr.get('OS-EXT-IPS:type') == 'floating':
                            floating_ips.append(addr.get('addr'))

                    # 为每个浮动IP创建实例信息
                    for fixed_ip in fixed_ips:
                        for floating_ip in floating_ips:
                            instance_infos.append(InstanceInfo(
                                instance_id=server.id,
                                fixed_ip=fixed_ip,
                                floating_ip=floating_ip
                            ))

            logger.info(f"Found {len(instance_infos)} instances with floating IPs")
            return instance_infos

        except Exception as e:
            logger.error(f"Failed to get instance information: {str(e)}")
            logger.error(f"Detailed error: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    def extract_ips_from_rules(self, current_rules):
        """从当前iptables规则中提取IP信息"""
        router_ips = set()  # 存储SNAT规则中的IP
        instance_ips = set()  # 存储实例规则中的IP
        
        for rule in current_rules:
            # 提取SNAT规则中的IP
            snat_match = re.search(r'traffic_snat_(\d+\.\d+\.\d+\.\d+)_[in|out]', rule)
            if snat_match:
                router_ips.add(snat_match.group(1))
                continue

            # 提取实例规则中的浮动IP
            vm_match = re.search(r'traffic_(\d+\.\d+\.\d+\.\d+)_vm_[in|out]', rule)
            if vm_match:
                instance_ips.add(vm_match.group(1))

        return {
            'router_ips': router_ips,
            'instance_ips': instance_ips
        }

    def extract_ips_from_ipset_rules(self, current_rules):
        ips = set()

        for rule in current_rules:
            ips.add(rule.split()[2])

        return ips

    def get_current_rules_for_namespace(self, namespace):
        """获取指定命名空间中的当前iptables规则"""
        try:
            # 使用bash -c来正确执行管道命令
            cmd = f"bash -c '/usr/sbin/ip netns exec {namespace} /usr/local/iptables/iptables-save -t mangle | grep traffic_'"
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()

            rules = []
            if process.returncode == 0:  # grep找到匹配项
                for line in stdout.splitlines():
                    if 'PREROUTING' in line:
                        rules.append(line.strip())
            elif process.returncode == 1:  # grep没有找到匹配项
                logger.info(f"No traffic rules found in namespace {namespace}")
            else:  # 其他错误
                logger.error(f"Error getting rules: {stderr}")
                raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)

            return rules
        except Exception as e:
            logger.error(f"Failed to get iptables rules in namespace {namespace}: {str(e)}")
            raise

    def get_current_ipset_rules_for_namespace(self, namespace):
        cmd = f'/usr/sbin/ipset list subnet1 -output save'

        stdout, stderr = self._run_cmd_in_namespace(namespace, cmd)

        if len(stderr):
            logger.error('Failed to get ipset rule')
            raise

        return stdout.split('\n')[1:-1]

    def generate_router_rules(self, router_info):
        """为路由器生成iptables规则，增加router_id在comment中"""
        rules = []
        rules.extend([
            f'-A PREROUTING -m set --match-set subnet1 src -m set ! --match-set subnet1 dst -m comment --comment "traffic_snat_{router_info.gateway_ip}_out router:{router_info.router_id}" -j traffic_chain',
            f'-A PREROUTING -m set -d {router_info.gateway_ip}/32 ! --match-set subnet1 src -m comment --comment "traffic_snat_{router_info.gateway_ip}_in router:{router_info.router_id}" -j traffic_chain'
        ])
        return rules

    def generate_instance_rules(self, instance_info):
        """为实例生成iptables规则，增加instance_id在comment中"""
        return [
            f'-A PREROUTING -s {instance_info.fixed_ip}/32 -m set ! --match-set subnet1 dst -m comment --comment "traffic_{instance_info.floating_ip}_vm_out instance:{instance_info.instance_id}" -j traffic_chain',
            f'-A PREROUTING -d {instance_info.floating_ip}/32 -m comment --comment "traffic_{instance_info.floating_ip}_vm_in instance:{instance_info.instance_id}" -j traffic_chain'
        ]

    def apply_rules_in_namespace(self, namespace, rules_to_add, rules_to_remove, ipset_rules_to_add, ipset_rules_to_remove):
        """在指定的命名空间中应用iptables规则变更"""
        try:
            # 打印ipset命令
            if ipset_rules_to_add or ipset_rules_to_remove:
                logger.info("\n=== IPSet Commands ===")
                for ipset_ip in ipset_rules_to_remove:
                    logger.info(f"ip netns exec {namespace} /usr/sbin/ipset del subnet1 {ipset_ip}")
                for ipset_ip in ipset_rules_to_add:
                    logger.info(f"ip netns exec {namespace} /usr/sbin/ipset add subnet1 {ipset_ip}")

            # 打印iptables命令
            if rules_to_add or rules_to_remove:
                logger.info("\n=== IPTables Commands ===")
                for rule in rules_to_remove:
                    if '-A ' in rule:
                        cmd = rule.replace('-A ', '-D ')
                        logger.info(f"ip netns exec {namespace} /usr/local/iptables/iptables -t mangle {cmd}")
                
                for rule in rules_to_add:
                    logger.info(f"ip netns exec {namespace} /usr/local/iptables/iptables -t mangle {rule}")

            # 实际执行ipset修改
            if len(ipset_rules_to_add) or len(ipset_rules_to_remove):
                config = ''
                for ipset_ip in ipset_rules_to_remove:
                    config += f'del -exist subnet1 {ipset_ip}\n'
                for ipset_ip in ipset_rules_to_add:
                    config += f'add -exist subnet1 {ipset_ip}\n'

                logger.info(f'/usr/sbin/ipset rules\n{config}')
                with open('/tmp/traffic_ipset.config', 'w') as f:
                    f.write(config)
                self._run_cmd_in_namespace(namespace, '/usr/sbin/ipset restore < /tmp/traffic_ipset.config')

            # 实际执行iptables修改
            if len(rules_to_add) or len(rules_to_remove):
                config = '*mangle\n'
                for rule in rules_to_remove:
                    if '-A ' in rule:
                        cmd = rule.replace('-A ', '-D ')
                        config += f'{cmd}\n'
                for rule in rules_to_add:
                    config += f'{rule}\n'
                config += 'COMMIT\n'

                logger.info(f'iptables rules\n{config}')
                with open('/tmp/traffic_iptables.config', 'w') as f:
                    f.write(config)
                self._run_cmd_in_namespace(namespace, '/usr/local/iptables/iptables-restore -n -T mangle /tmp/traffic_iptables.config')

        except Exception as e:
            logger.error(f"Failed to apply iptables rules in namespace {namespace}: {str(e)}")
            raise

    def get_router_instance_mapping(self):
        """
        获取路由器和其关联实例的映射关系
        通过更精确的端口和子网关系查找路由器和实例的对应关系

        Returns:
            Dict[str, List[InstanceInfo]]: 路由器ID到实例信息的映射
        """
        try:
            router_instances = {}  # 存储路由器到实例的映射
            router_subnet_map = {} # 存储路由器到子网的映射
            instance_subnet_map = {} # 存储实例到子网的映射

            # 1. 获取所有路由器的接口信息
            for router in self.conn.network.routers():
                router_id = router.id
                router_instances[router_id] = []
                router_subnet_map[router_id] = set()

                # 获取路由器的所有接口端口
                router_ports = list(self.conn.network.ports(
                    device_id=router_id,
                    device_owner='network:router_interface'
                ))
                router_ports.extend(list(self.conn.network.ports(
                    device_id=router_id,
                    device_owner='network:ha_router_replicated_interface'
                )))

                # 记录路由器连接的所有子网
                for port in router_ports:
                    for fixed_ip in getattr(port, 'fixed_ips', []) or []:
                        subnet_id = fixed_ip.get('subnet_id')
                        if subnet_id:
                            router_subnet_map[router_id].add(subnet_id)
                            logger.info(f"Router {router_id} connected to subnet {subnet_id}")

            # 2. 获取所有实例信息
            instance_infos = self.get_instance_infos()
            for instance in instance_infos:
                try:
                    # 获取实例的所有端口，使用更精确的查询
                    instance_ports = list(self.conn.network.ports(
                        fixed_ips=f"ip_address={instance.fixed_ip}",
                        device_owner=['compute:nova', 'compute:None']  # 包含可能的设备所有者类型
                    ))

                    if not instance_ports:
                        logger.warning(f"No ports found for instance {instance.instance_id} with fixed IP {instance.fixed_ip}")
                        continue

                    # 处理实例的每个端口
                    for port in instance_ports:
                        port_subnets = set()
                        # 获取端口关联的所有子网
                        for fixed_ip in getattr(port, 'fixed_ips', []) or []:
                            subnet_id = fixed_ip.get('subnet_id')
                            if subnet_id:
                                port_subnets.add(subnet_id)
                                instance_subnet_map[instance.instance_id] = port_subnets

                        # 根据子网关系建立实例和路由器的映射
                        for router_id, router_subnets in router_subnet_map.items():
                            # 如果实例的任一子网与路由器的子网有交集
                            if port_subnets & router_subnets:
                                if instance not in router_instances[router_id]:
                                    router_instances[router_id].append(instance)
                                    logger.info(
                                        f"Mapped instance {instance.instance_id} "
                                        f"(fixed IP: {instance.fixed_ip}, floating IP: {instance.floating_ip}) "
                                        f"to router {router_id} through subnet(s): {port_subnets & router_subnets}"
                                    )

                except Exception as e:
                    logger.error(f"Error processing instance {instance.instance_id}: {str(e)}")
                    continue

            # 3. 记录最终的映射统计
            for router_id, instances in router_instances.items():
                logger.info(f"Router {router_id} summary:")
                logger.info(f"  Connected subnets: {router_subnet_map[router_id]}")
                logger.info(f"  Total connected instances: {len(instances)}")

                # 详细记录每个实例的信息
                for instance in instances:
                    logger.info(
                        f"  Instance {instance.instance_id}:"
                        f" Fixed IP: {instance.fixed_ip},"
                        f" Floating IP: {instance.floating_ip},"
                        f" Subnets: {instance_subnet_map.get(instance.instance_id, set())}"
                    )

            return router_instances

        except Exception as e:
            logger.error(f"Failed to get router-instance mapping: {str(e)}")
            logger.exception("Detailed traceback:")
            raise

    def update_rules(self):
        """更新所有命名空间中的iptables规则"""
        try:
            # 获取所有路由器命名空间
            namespaces = self.get_router_namespaces()
            logger.info(f"Found namespaces: {namespaces}")

            # 获取路由器和实例的映射关系
            router_instance_mapping = self.get_router_instance_mapping()
            logger.info("Got router-instance mapping")

            # 获取所有路由器信息
            router_infos = self.get_router_infos()

            for namespace in namespaces:
                logger.info(f"Processing namespace: {namespace}")
                router_id = namespace.replace('qrouter-', '')

                # 获取当前路由器的信息
                router_info = next((ri for ri in router_infos if ri.router_id == router_id), None)
                if not router_info:
                    logger.warning(f"No router info found for namespace {namespace}")
                    continue

                # 首先初始化必要的链和ipset
                self.init_iptables_in_namespace(namespace)

                # 生成规则集合
                rules_to_add = set()
                rules_to_remove = set()

                # 获取当前路由器关联的实例
                router_instances = router_instance_mapping.get(router_id, [])
                logger.info(f"Found {len(router_instances)} instances for router {router_id}")

                # 获取当前命名空间中的规则
                current_rules_list = self.get_current_rules_for_namespace(namespace)
                current_rules = set()

                # 检查重复的规则
                for i in current_rules_list:
                    if i in current_rules:
                        rules_to_remove.add(i)
                    else:
                        current_rules.add(i)

                current_ips = self.extract_ips_from_rules(current_rules)
                current_ipset_rules = self.get_current_ipset_rules_for_namespace(namespace)
                current_ipset_ips = self.extract_ips_from_ipset_rules(current_ipset_rules)

                # 获取当前路由器的实际IP
                api_router_ips = {router_info.gateway_ip}
                api_instance_ips = {instance.floating_ip for instance in router_instances}

                # 计算需要删除的IP
                router_ips_to_remove = current_ips['router_ips'] - api_router_ips
                instance_ips_to_remove = current_ips['instance_ips'] - api_instance_ips

                # 计算需要添加的IP
                router_ips_to_add = api_router_ips - current_ips['router_ips']
                instance_ips_to_add = api_instance_ips - current_ips['instance_ips']

                # 生成需要删除的规则
                for rule in current_rules:
                    # 检查SNAT规则
                    for ip in router_ips_to_remove:
                        if f'traffic_snat_{ip}_' in rule:
                            rules_to_remove.add(rule)
                    # 检查实例规则
                    for ip in instance_ips_to_remove:
                        if f'traffic_{ip}_vm_' in rule:
                            rules_to_remove.add(rule)

                # 生成需要添加的路由器规则
                if router_info.gateway_ip in router_ips_to_add:
                    rules_to_add.update(self.generate_router_rules(router_info))

                # 生成需要添加的实例规则
                for instance in router_instances:
                    if instance.floating_ip in instance_ips_to_add:
                        rules_to_add.update(self.generate_instance_rules(instance))

                # ipset规则
                for i in [instance.fixed_ip for instance in router_instances]:
                    router_info.instance_ips.remove(i)

                ipset_rules_to_add = set(router_info.instance_ips) - current_ipset_ips
                ipset_rules_to_remove = current_ipset_ips - set(router_info.instance_ips)

                # 输出变更信息
                logger.info(f"Namespace {namespace} - Changes to apply:")
                logger.info(f"Router IPs to remove: {router_ips_to_remove}")
                logger.info(f"Instance IPs to remove: {instance_ips_to_remove}")
                logger.info(f"Ipset IPs to remove: {ipset_rules_to_remove}")
                logger.info(f"Router IPs to add: {router_ips_to_add}")
                logger.info(f"Instance IPs to add: {instance_ips_to_add}")
                logger.info(f"Ipset IPs to add: {ipset_rules_to_add}")

                if rules_to_add or rules_to_remove or ipset_rules_to_add or ipset_rules_to_remove:
                    logger.info(f"Applying changes in namespace {namespace}")
                    self.apply_rules_in_namespace(namespace, rules_to_add, rules_to_remove, ipset_rules_to_add, ipset_rules_to_remove)
                else:
                    logger.info(f"No rules need to be updated in namespace {namespace}")

        except Exception as e:
            logger.error(f"Error updating rules: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def __del__(self):
        """清理OpenStack连接"""
        if hasattr(self, 'conn'):
            self.conn.close()

def main():
    try:
        required_cmds = [
            '/usr/local/iptables/iptables',
            '/usr/local/iptables/iptables-save',
            '/usr/sbin/ipset',
            '/usr/sbin/ip'
        ]

        for cmd in required_cmds:
            if not os.path.exists(cmd):
                logger.error(f'{cmd} not exist')
                sys.exit(1)

        manager = IPTablesManager()
        manager.update_rules()
    except Exception as e:
        logger.error(f"Script execution failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
