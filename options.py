import os.path as path

class Get:
    def read(self):
        if not path.exists("config_custom.txt"):
            lines = [line.rstrip('\n') for line in open('config.txt')]
        else:
            lines = [line.rstrip('\n') for line in open('config_custom.txt')]

        for line in lines:
            if "pool_ip=" in line:
                self.pool_ip_conf = line.replace('pool_ip=', '')
            if "miner_address=" in line:
                self.miner_address_conf = line.replace('miner_address=', '')
            if "miner_name=" in line:
                self.miner_name_conf = line.replace('miner_name=', '')
            if "miner_debug=" in line:
                self.miner_debug_conf = line.replace('miner_debug=', '')
            if "opencl_hash_count=" in line:
                self.opencl_hash_count_conf = int(line.replace('opencl_hash_count=', ''))
            if "opencl_timeout=" in line:
                self.opencl_timeout_conf = int(line.replace('opencl_timeout=', ''))
            if "opencl_thread_multiplier=" in line:
                self.opencl_thread_multiplier_conf = int(line.replace('opencl_thread_multiplier=', ''))
            if "opencl_full_check=" in line:
                self.opencl_full_check_conf= int(line.replace('opencl_full_check=', ''))
            if "opencl_disable_device=" in line:
                str = line.replace('opencl_disable_device=', '')
                self.opencl_disable_device_conf = [int(d.strip()) for d in str.split(",") if len(d.strip()) > 0 ]
