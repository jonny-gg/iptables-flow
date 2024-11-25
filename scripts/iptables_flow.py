#!/usr/local/iptables/venv/bin/python
import json
import time
import asyncio
import re
import os
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import aiofiles
import fcntl
import sys
import random
import concurrent.futures
from typing import List, Dict, Optional, Any, Tuple, Union  # 添加 Tuple 的导入

# 配置日志
os.makedirs('/logs/iptables', exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,  # 使用DEBUG级别方便排查问题
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/iptables/traffic_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def get_minute_aligned_timestamp() -> int:
    """Get timestamp aligned to minute"""
    current_time = int(time.time())
    return current_time - (current_time % 60)

@contextmanager
def performance_logger(operation: str):
    """性能监控上下文管理器"""
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        logger.info(f"{operation} took {duration:.2f} seconds")

@dataclass
class TrafficStat:
    """流量统计数据类"""
    floating_dev_id: str
    floating_ip: str
    region: str
    rx: int
    tx: int
    timestamp: int

class NetworkNamespaceManager:
    """网络命名空间管理器"""
    def __init__(self):
        self.namespaces = []
        self.ns_pattern = re.compile(r'qrouter-[a-f0-9-]+')

    async def get_namespaces(self) -> List[str]:
        """异步获取网络命名空间列表"""
        try:
            with performance_logger("Get network namespaces"):
                proc = await asyncio.create_subprocess_exec(
                    '/usr/sbin/ip', 'netns',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, _ = await proc.communicate()

                namespaces = []
                for line in stdout.decode().splitlines():
                    match = self.ns_pattern.search(line)
                    if match:
                        namespaces.append(match.group())

                logger.info(f"Found {len(namespaces)} router namespaces")
                self.namespaces = namespaces
                return namespaces

        except Exception as e:
            logger.error(f"Error getting network namespaces: {e}")
            return []
        
class IPTablesManager:
    """iptables规则管理器"""
    def __init__(self):
        # 更新正则表达式以匹配实际的输出格式
        self.traffic_pattern = re.compile(r'/\* traffic_(?:snat_)?(\d+\.\d+\.\d+\.\d+)_(?:vm_|snat_)?(?:in|out)(?: (?:router|instance):([a-f0-9-]+)).*? \*/')
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        self.max_retries = 3
        self.wait_time = 3
        self.retry_delay = 1

    async def get_rules(self, namespace: str, attempt: int = 0) -> List[Dict[str, Any]]:
        """异步获取单个命名空间的iptables规则"""
        try:
            with performance_logger(f"Get iptables rules for {namespace}"):
                cmd = [
                    '/usr/sbin/ip', 'netns', 'exec', namespace,
                    '/usr/local/iptables/iptables',
                    '-w', str(self.wait_time),
                    '-t', 'mangle', '-L', 'PREROUTING', '-nvx'
                ]

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await proc.communicate()
                stdout_str = stdout.decode()
                logger.debug(f"Raw iptables output for {namespace}:\n{stdout_str}")

                if proc.returncode != 0:
                    error_msg = stderr.decode()
                    if "xtables lock" in error_msg and attempt < self.max_retries:
                        logger.warning(f"Lock conflict for {namespace}, retry {attempt + 1}/{self.max_retries}")
                        await asyncio.sleep(self.retry_delay * (attempt + 1))
                        return await self.get_rules(namespace, attempt + 1)
                    else:
                        logger.error(f"Error executing iptables in {namespace}: {error_msg}")
                        return []

                rules = self._parse_iptables_output(stdout_str)
                logger.info(f"Found {len(rules)} rules in namespace {namespace}")
                return rules

        except Exception as e:
            logger.error(f"Error getting iptables rules for {namespace}: {e}")
            return []

    def _parse_iptables_output(self, output: str) -> List[Dict[str, Any]]:
        """解析iptables输出，合并相同floating_dev_id的入站和出站流量"""
        # 使用字典临时存储合并的规则
        merged_rules = {}
        
        for line in output.splitlines():
            if 'traffic_' not in line:
                continue

            try:
                rule = self._parse_single_rule(line)
                if not rule:
                    continue
                    
                # 使用floating_ip和floating_dev_id组合作为键
                key = f"{rule['floating_ip']}_{rule['floating_dev_id']}"
                
                if key not in merged_rules:
                    merged_rules[key] = rule
                else:
                    # 更新已存在的规则，合并rx和tx
                    existing_rule = merged_rules[key]
                    existing_rule['rx'] = max(existing_rule['rx'], rule['rx'])
                    existing_rule['tx'] = max(existing_rule['tx'], rule['tx'])
                    
                logger.debug(f"Merged rule for {key}: {merged_rules[key]}")
                
            except Exception as e:
                logger.error(f"Error parsing rule: {e}, line: {line}")
                continue

        return list(merged_rules.values())

    def _parse_single_rule(self, line: str) -> Optional[Dict[str, Any]]:
        """解析单条iptables规则"""
        try:
            parts = line.strip().split()
            if len(parts) < 2:
                logger.debug(f"Line too short: {line}")
                return None

            bytes_count = int(parts[1])
            logger.debug(f"Processing line with bytes {bytes_count}: {line}")

            comment_match = self.traffic_pattern.search(line)
            if not comment_match:
                logger.debug(f"No pattern match for line: {line}")
                return None

            floating_ip = comment_match.group(1)
            dev_id = comment_match.group(2)
            
            if not dev_id:
                logger.debug(f"No device ID found in line: {line}")
                return None

            # 判断是入站还是出站流量
            is_in = '_in' in line

            rule = {
                'floating_ip': floating_ip,
                'floating_dev_id': dev_id,
                'rx': bytes_count if is_in else 0,
                'tx': bytes_count if not is_in else 0,
                'timestamp': get_minute_aligned_timestamp()
            }
            logger.debug(f"Created rule: {rule}")
            return rule

        except Exception as e:
            logger.error(f"Error parsing single rule: {e}, line: {line}")
            return None

    async def process_namespaces(self, namespaces: List[str]) -> List[Dict[str, Any]]:
        """并行处理多个命名空间的iptables规则"""
        sem = asyncio.Semaphore(3)

        async def process_with_semaphore(ns: str) -> List[Dict[str, Any]]:
            async with sem:
                await asyncio.sleep(random.uniform(0, 0.5))
                return await self.get_rules(ns)

        shuffled_namespaces = namespaces.copy()
        random.shuffle(shuffled_namespaces)

        tasks = [asyncio.ensure_future(process_with_semaphore(ns)) 
                for ns in shuffled_namespaces]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"Error processing namespaces: {e}")
            results = []

        all_rules = []
        success_count = 0
        error_count = 0

        for ns_rules in results:
            if isinstance(ns_rules, Exception):
                logger.error(f"Error processing namespace: {ns_rules}")
                error_count += 1
                continue
            if ns_rules:
                success_count += 1
                all_rules.extend(ns_rules)

        total_count = len(namespaces)
        logger.info(f"Processed {total_count} namespaces: {success_count} successful, {error_count} failed")
        logger.debug(f"All collected rules: {all_rules}")

        return all_rules
    
class FileManager:
    """文件操作管理器"""
    def __init__(self,
                 primary_dir: str = "/usr/local/iptables/traffic_stats",
                 secondary_dir: str = "/usr/local/iptables/traffic_stats_backup"):
        self.primary_dir = primary_dir
        self.secondary_dir = secondary_dir
        self.cache_file = os.path.join(primary_dir, "traffic_stats.json")
        self.ensure_directories()

    def ensure_directories(self):
        """确保必要的目录存在"""
        try:
            for directory in [self.primary_dir, self.secondary_dir]:
                os.makedirs(directory, mode=0o755, exist_ok=True)
                logger.info(f"Ensured directory exists: {directory}")
        except Exception as e:
            logger.error(f"Error creating directories: {e}")
            raise

    def get_csv_filenames(self) -> Tuple[str, str]:
        """生成当天的CSV文件名"""
        current_date = datetime.now().strftime("%Y%m%d")
        primary_file = os.path.join(self.primary_dir, f"traffic_stats_{current_date}.csv")
        secondary_file = os.path.join(self.secondary_dir, f"traffic_stats_{current_date}.csv")
        return primary_file, secondary_file

    async def write_csv(self, stats: List[TrafficStat], is_baseline: bool = False) -> bool:
        """异步写入CSV文件到两个目录
        
        Args:
            stats: 流量统计数据列表
            is_baseline: 是否是基准值
        """
        if not stats:
            return True

        try:
            with performance_logger("Write CSV to both directories"):
                primary_file, secondary_file = self.get_csv_filenames()
                
                # 准备数据
                rows = []
                current_timestamp = get_minute_aligned_timestamp()
                current_time = datetime.fromtimestamp(current_timestamp).strftime("%H:%M")
                
                for stat in stats:
                    row = [
                        stat.floating_dev_id,
                        stat.floating_ip,
                        stat.region,
                        f"{stat.rx:.2f}",  # 保留2位小数
                        f"{stat.tx:.2f}",  # 保留2位小数
                        str(current_timestamp),
                        current_time,
                        'baseline' if is_baseline else 'increment'
                    ]
                    rows.append(','.join(row))

                # 写入数据
                async def write_file(filepath: str) -> bool:
                    try:
                        async with aiofiles.open(filepath, mode='a', newline='') as f:
                            await f.write('\n'.join(rows) + '\n')
                        return True
                    except Exception as e:
                        logger.error(f"Error writing to {filepath}: {e}")
                        return False

                # 并发写入两个目录
                results = await asyncio.gather(
                    write_file(primary_file),
                    write_file(secondary_file),
                    return_exceptions=True
                )

                success = all(isinstance(r, bool) and r for r in results)
                if success:
                    logger.info(
                        f"Successfully wrote {len(stats)} records "
                        f"({'baseline' if is_baseline else 'increment'}) "
                        f"to both directories"
                    )
                else:
                    logger.error("Failed to write to one or both directories")

                return success

        except Exception as e:
            logger.error(f"Error writing CSV files: {e}")
            return False

    async def cleanup_old_files(self, keep_days: int = 15):
        """异步清理旧文件"""
        try:
            # 使用日期而不是时间戳，避免时间精度问题
            current_date = datetime.now().date()
            total_deleted = 0

            for directory in [self.primary_dir, self.secondary_dir]:
                deleted_count = 0

                for filename in os.listdir(directory):
                    if not filename.startswith('traffic_stats_') or not filename.endswith('.csv'):
                        continue

                    filepath = os.path.join(directory, filename)

                    # 从文件名提取日期
                    try:
                        date_str = filename.split('_')[2].split('.')[0]  # YYYYMMDD
                        file_date = datetime.strptime(date_str, '%Y%m%d').date()
                    except:
                        # 如果无法从文件名解析日期，使用文件修改时间的日期部分
                        file_date = datetime.fromtimestamp(os.path.getmtime(filepath)).date()

                    # 计算天数差（使用日期差）
                    days_diff = (current_date - file_date).days
                    
                    # 记录日志，帮助调试
                    logger.debug(f"File: {filename}, Current date: {current_date}, File date: {file_date}, Days diff: {days_diff}")

                    # 只有当天数差大于或等于keep_days时才删除
                    if days_diff >= keep_days:
                        try:
                            logger.info(f"Attempting to delete {filepath} (age: {days_diff} days)")
                            os.remove(filepath)
                            deleted_count += 1
                            logger.info(f"Successfully deleted {filepath}")
                        except Exception as e:
                            logger.error(f"Error deleting old file {filepath}: {e}")
                    else:
                        logger.debug(f"Keeping {filepath} (age: {days_diff} days)")

                total_deleted += deleted_count
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old files from {directory}")

            if total_deleted > 0:
                logger.info(f"Total files cleaned up: {total_deleted}")

        except Exception as e:
            logger.error(f"Error during file cleanup: {e}")
            logger.exception(e)  # 输出完整的错误堆栈

    async def read_cache(self) -> Dict:
        """异步读取缓存文件"""
        try:
            if not os.path.exists(self.cache_file):
                return {}

            async with aiofiles.open(self.cache_file, 'r') as f:
                content = await f.read()
                return json.loads(content)

        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return {}

    async def write_cache(self, stats: List[TrafficStat]):
        """异步写入缓存文件"""
        try:
            stats_dict = {
                f"{stat.floating_ip}_{stat.floating_dev_id}": stat.__dict__
                for stat in stats
            }

            temp_file = f"{self.cache_file}.tmp"

            async with aiofiles.open(temp_file, 'w') as f:
                await f.write(json.dumps(stats_dict, indent=2))

            os.rename(temp_file, self.cache_file)

        except Exception as e:
            logger.error(f"Error writing cache: {e}")
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class IPTablesLock:
    """iptables锁管理器"""
    def __init__(self, lock_file: str = '/usr/local/iptables/.traffic_monitor.lock'):
        self.lock_file = lock_file
        self.lock_fd = None

    async def acquire(self) -> bool:
        """异步获取锁"""
        try:
            loop = asyncio.get_event_loop()
            self.lock_fd = open(self.lock_file, 'w')

            # 在线程池中执行阻塞的fcntl操作
            await loop.run_in_executor(
                None,
                lambda: fcntl.flock(self.lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            )
            return True

        except IOError:
            logger.warning("Another instance is running")
            if self.lock_fd:
                self.lock_fd.close()
            return False
        except Exception as e:
            logger.error(f"Error acquiring lock: {e}")
            if self.lock_fd:
                self.lock_fd.close()
            return False

    async def release(self):
        """异步释放锁"""
        if self.lock_fd:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: fcntl.flock(self.lock_fd.fileno(), fcntl.LOCK_UN)
                )
                self.lock_fd.close()
            except Exception as e:
                logger.error(f"Error releasing lock: {e}")

class TrafficMonitor:
    """流量监控主类"""
    def __init__(self):
        self.namespace_manager = NetworkNamespaceManager()
        self.iptables_manager = IPTablesManager()
        self.file_manager = FileManager(
            primary_dir="/usr/local/iptables/traffic_stats",
            secondary_dir="/usr/local/iptables/traffic_stats_backup"
        )
        self.lock_manager = IPTablesLock()
        self.region = self._load_region()
        self.max_reasonable_increment_bps = 100 * 1024 * 1024 * 1024  # 100 GB
        logger.info(f"Using region: {self.region}")
        
    def _convert_to_bps(self, bytes_value: int, interval_seconds: int = 60) -> int:
        """将字节数转换为比特每秒
        
        Args:
            bytes_value: 字节数
            interval_seconds: 统计间隔（默认60秒）
            
        Returns:
            int: 比特每秒
        """
        try:
            # bytes -> bits -> bps
            return round((bytes_value) / interval_seconds, 2)
        except Exception as e:
            logger.error(f"Error converting to bps: {e}")
            return 0
        
    def _load_region(self) -> str:
        """从openrc文件加载region信息"""
        try:
            cmd = ['bash', '-c', 'source /usr/local/iptables/admin-openrc.sh && echo $OS_REGION_NAME']
            import subprocess
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                region = result.stdout.decode().strip()
                if region:
                    return region
            
            # 如果上面的方法失败，尝试直接执行source命令
            cmd = '. /usr/local/iptables/admin-openrc.sh && echo $OS_REGION_NAME'
            region = os.popen(cmd).read().strip()
            if region:
                return region

            # 如果还是获取失败，返回默认值
            return os.getenv('OS_REGION_NAME', 'RegionOne_S3_Public')
            
        except Exception as e:
            logger.error(f"Error loading region from openrc: {e}")
            return os.getenv('OS_REGION_NAME', 'RegionOne_S3_Public')

    async def process_traffic_stats(self) -> List[TrafficStat]:
        """处理流量统计"""
        try:
            namespaces = await self.namespace_manager.get_namespaces()
            if not namespaces:
                logger.warning("No network namespaces found")
                return []

            rules = await self.iptables_manager.process_namespaces(namespaces)
            if not rules:
                logger.warning("No iptables rules found")
                return []

            traffic_stats = []
            for rule in rules:
                stat = TrafficStat(
                    floating_dev_id=rule['floating_dev_id'],
                    floating_ip=rule['floating_ip'],
                    region=self.region,
                    rx=rule['rx'],
                    tx=rule['tx'],
                    timestamp=rule['timestamp']
                )
                traffic_stats.append(stat)

            logger.debug(f"Processed traffic stats: {traffic_stats}")
            return traffic_stats

        except Exception as e:
            logger.error(f"Error processing traffic stats: {e}")
            return []

    async def calculate_stats(
        self,
        current_stats: List[TrafficStat],
        previous_stats: Dict
    ) -> Tuple[List[TrafficStat], bool]:
        """计算流量统计（以Bps为单位，保留2位小数）
        
        Returns:
            Tuple[List[TrafficStat], bool]: (统计数据, 是否为基准值)
        """
        try:
            stats = []
            current_timestamp = get_minute_aligned_timestamp()
            is_baseline = not bool(previous_stats)  # 如果没有前值，则为基准值

            if is_baseline:
                # 第一次运行，记录基准值（转换为Bps）
                logger.info("First run, recording baseline values")
                baseline_stats = []
                for stat in current_stats:
                    baseline_stat = TrafficStat(
                        floating_dev_id=stat.floating_dev_id,
                        floating_ip=stat.floating_ip,
                        region=stat.region,
                        rx=self._convert_to_bps(stat.rx),  # 转换为Bps
                        tx=self._convert_to_bps(stat.tx),  # 转换为Bps
                        timestamp=stat.timestamp
                    )
                    baseline_stats.append(baseline_stat)
                return baseline_stats, True

            # 计算增量
            new_ips_found = False  # 用于跟踪是否发现新IP

            for current in current_stats:
                key = f"{current.floating_ip}_{current.floating_dev_id}"
                previous = previous_stats.get(key, {})

                # 如果是新的 IP，记录其基准值
                if not previous:
                    logger.info(f"New IP detected: {key}, recording baseline")
                    baseline_stat = TrafficStat(
                        floating_dev_id=current.floating_dev_id,
                        floating_ip=current.floating_ip,
                        region=current.region,
                        rx=self._convert_to_bps(current.rx),  # 转换为Bps
                        tx=self._convert_to_bps(current.tx),  # 转换为Bps
                        timestamp=current.timestamp
                    )
                    stats.append(baseline_stat)
                    new_ips_found = True
                    continue

                # 获取前一次的时间戳
                prev_timestamp = previous.get('timestamp', 0)
                
                # 计算时间差（秒）
                time_diff_seconds = current_timestamp - prev_timestamp
                
                # 检查时间差异
                if time_diff_seconds <= 0 or time_diff_seconds > 300:  # 5分钟
                    logger.warning(
                        f"Unusual time difference for {key}: {time_diff_seconds} seconds. "
                        f"Current: {current_timestamp}, Previous: {prev_timestamp}"
                    )
                    continue

                # 计算字节增量
                rx_bytes_increment = max(0, current.rx - previous.get('rx', 0))
                tx_bytes_increment = max(0, current.tx - previous.get('tx', 0))

                # 转换为Bps
                rx_bps = self._convert_to_bps(rx_bytes_increment, time_diff_seconds)
                tx_bps = self._convert_to_bps(tx_bytes_increment, time_diff_seconds)

                # 检查增量合理性
                if rx_bps > self.max_reasonable_increment_bps or tx_bps > self.max_reasonable_increment_bps:
                    logger.warning(
                        f"Unusually large increment detected for {key}: "
                        f"RX: {rx_bps:.2f} bps, TX: {tx_bps:.2f} bps"
                    )
                    continue

                # 记录Bps
                increment = TrafficStat(
                    floating_dev_id=current.floating_dev_id,
                    floating_ip=current.floating_ip,
                    region=current.region,
                    rx=rx_bps,
                    tx=tx_bps,
                    timestamp=current_timestamp
                )
                stats.append(increment)
                logger.debug(
                    f"Recorded increment for {key}: "
                    f"RX: {rx_bps:.2f} bps, TX: {tx_bps:.2f} bps"
                )

            logger.info(f"Calculated {len(stats)} records")
            return stats, new_ips_found

        except Exception as e:
            logger.error(f"Error calculating stats: {e}")
            return [], False

    async def run(self):
        """主执行流程"""
        try:
            if not await self.lock_manager.acquire():
                return

            try:
                # 读取上一次的统计数据
                previous_stats = await self.file_manager.read_cache()
                
                # 获取当前统计数据
                current_stats = await self.process_traffic_stats()
                
                if current_stats:
                    # 先保存当前数据到缓存
                    await self.file_manager.write_cache(current_stats)
                    
                    # 计算统计数据
                    stats, is_baseline = await self.calculate_stats(current_stats, previous_stats)
                    
                    # 如果有数据，写入 CSV
                    if stats:
                        await self.file_manager.write_csv(stats, is_baseline)
                    else:
                        logger.info("No stats to write")

                # 清理旧文件
                await self.file_manager.cleanup_old_files()

            finally:
                await self.lock_manager.release()

        except Exception as e:
            logger.error(f"Error in main execution: {e}")


async def main():
    """主函数"""
    monitor = TrafficMonitor()
    await monitor.run()


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
        loop.close()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
