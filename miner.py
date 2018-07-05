import hashlib
import json
import options
import re
import signal
import socket
import socks
import sys
import time

# OpenCL miner specific
import clminer
import numpy as np
import threading
import queue

# load config
config = options.Get()
config.read()
pool_ip = config.pool_ip_conf
miner_address = config.miner_address_conf
miner_name = config.miner_name_conf
miner_version = '0.1'

try:
    miner_debug = eval(config.miner_debug_conf)
except:
    miner_debug = False

# OpenCL miner specific
# OpenCL config
opencl_full_check = config.opencl_full_check_conf
opencl_timeout = 0

pool_socket = None
pool_get_work_data_set = list()


def get_socket():
    global pool_socket, pool_ip
    if pool_socket is None:
        while pool_socket is None:
            print("=> Re-connecting")
            try:
                test_socket = socks.socksocket()
                ip_addr = socket.gethostbyname(pool_ip)
                test_socket.connect((ip_addr, int(8028)))
                test_socket.setblocking(1)
                pool_socket = test_socket
            except Exception as e:
                print("=> Connection failed...")
                print(str(e))
                time.sleep(2)
                pass

    return pool_socket


def clear_socket():
    global pool_socket
    pool_socket = None


def send_string_message(sdef, data):
    send_string  = str(json.dumps(data))
    send_string += ("%c%c" % (0xd, 0xa))
    sdef.sendall(send_string.encode("utf-8"))


def receive_string_message(sdef):
    received_data = b''
    data = ' '
    while ord(data) != 0xa:
        try:
            data = sdef.recv(1)
            received_data += data
        except Exception as e:
            raise RuntimeError("Connection closed by the remote host (%s)" % str(e))
    return json.loads(''.join(received_data.decode("utf-8")))


def bin_convert(string):
    bin_format_dict = dict((x, format(ord(x), '8b').replace(' ', '0')) for x in '0123456789abcdef')
    return ''.join(bin_format_dict[x] for x in string)


def diff_me(address, nonce, db_block_hash):
    diff_broke = 0
    diff = 0
    hash = hashlib.sha224((address + nonce + db_block_hash).encode("utf-8")).hexdigest()
    mining_hash = bin_convert(hash)
    while diff_broke == 0:
        mining_condition = bin_convert(db_block_hash)[0:diff]
        if mining_condition in mining_hash:
            diff_result = diff
            diff = diff + 1
        else:
            diff_broke = 1

    return diff_result


def address_validate(address):
    if re.match ('[abcdef0123456789]{56}', address):
        return True
    else:
        return False

def s_test(testString):
    return (len(testString)==56) and address_validate(testString)


def submit_share(thread_id, address, nonce, block_hash, difficulty, hashrate):
    global miner_address, miner_name
    mining_condition = bin_convert(block_hash)[0:difficulty]
    mining_hash = bin_convert(hashlib.sha224((address + nonce + block_hash).encode("ascii")).hexdigest())

    difficulty_actual = diff_me(address, nonce, block_hash)
    if miner_debug:
        print("Thread{}: Found solution: difficulty:({}/{}) Nonce: {}".format(
            thread_id, difficulty_actual, difficulty, nonce))

    if mining_condition not in mining_hash:
        return False

    try:
        block_timestamp = '%.2f' % time.time()
        packet = dict()
        packet['mineraddress'] = miner_address
        packet['minername'] = miner_name
        packet['blocktimestamp'] = block_timestamp
        packet['nonce'] = nonce
        packet['mrate'] = hashrate
        packet['blockhash'] = block_hash
        packet['numworker'] = 1

        print("Thread{}: Sending solution: difficulty:({}/{}) Nonce: {}".format(
            thread_id, difficulty_actual, difficulty, nonce))

        send_string_message(get_socket(), packet)

    except Exception as e:
        print("Share submission failed: (%s)" % str(e))
        return False

    return True


def get_work():
    global pool_get_work_data_set
    while True:
        try:
            data = receive_string_message(get_socket())
        except Exception as e:
            print("Connection failed: getwork %s" % str(e))
            clear_socket()
            continue

        pool_address = str(data['pooladdress'])
        block_hash = str(data['netblockhash'])
        difficulty_pool = int(data['pooldiff'])
        difficulty_network = int(data['netdiff'])
        pool_get_work_data_set = [
            block_hash, difficulty_pool, pool_address, difficulty_network
        ]
        print("==>Getwork: BlockHash: {} Pool/Network Difficulty: {}/{} ".format(
            block_hash, difficulty_pool, difficulty_network))


def signal_handler(signal, frame):
    print("pressed control-C")
    print("=============================================")
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    result_queue = clminer.oclResultQueue()
    stats_queue = queue.Queue()

    # Check miner address
    if not s_test(miner_address):
        print("Invalid miner_address, please double check and try again")
        sys.exit(0)

    print("Coinsaurus Open Source Miner version {}".format(miner_version))
    print("Miner Address : {}".format(miner_address))
    print("Miner Name    : {}".format(miner_name))

    # Start get work thread
    print("Starting Thread")
    get_work_thread = threading.Thread(target=get_work)
    get_work_thread.daemon = True
    get_work_thread.start()

    # Wait for work from the Pool before starting the miners
    while len(pool_get_work_data_set) == 0:
        time.sleep(0.5)

    pool_address = pool_get_work_data_set[2]
    diff = pool_get_work_data_set[1]
    db_block_hash = None

    opcl = clminer.ocl()
    opcl.setupCL(result_queue, stats_queue)
    opencl_timeout = opcl.getTimeout()

    miners = opcl.getMiners()

    # OpenCL Hash parameters
    for m in miners:
        m.setHeader(pool_address.encode('utf-8'))

    print("NOTE: Stats are printed on get work")
    thread_hash_rate_history = dict()
    shares_submitted = 0
    total_hash_rate = 0

    while True:
        try:
            if db_block_hash != pool_get_work_data_set[0]:
                if db_block_hash is not None:
                    hash_rate = dict()
                    for thread_id in thread_hash_rate_history:
                        if len(thread_hash_rate_history[thread_id]):
                            hash_rate[thread_id] = \
                                sum(thread_hash_rate_history[thread_id])/float(len(thread_hash_rate_history[thread_id]))
                        else:
                            hash_rate[thread_id] = 0.0
                    total_hash_rate = sum(hash_rate.values()) / 1e6
                    output_string = "Total Hash Rate: {:,.2f} Mh/s Submitted Shares: {} | ".format(
                        total_hash_rate, shares_submitted)

                    for thread_id in hash_rate:
                        output_string += "Thread{}: {:,.2f} Mh/s ".format(thread_id, hash_rate[thread_id] / 1e6)
                    print(output_string)

                    for thread_id in thread_hash_rate_history:
                        thread_hash_rate_history[thread_id].clear()

                pool_address = pool_get_work_data_set[2]
                diff = pool_get_work_data_set[1]
                db_block_hash = pool_get_work_data_set[0]

                if opencl_full_check == 1:
                    searchKey = np.uint32(int(diff))
                    print("Difficulty: {}".format(searchKey))
                else:
                    searchKey = np.uint32(int(db_block_hash[:8], 16))
                    print("Search key: {:x}".format(searchKey))

                for m in miners:
                    m.setTail(db_block_hash.encode('utf-8'))
                    m.setKernelParams(searchKey)
                    m.startMining()

            cand, rq_length = result_queue.getNextCandidate(timeout=0.02)
            if cand is not None:
                candidate = cand[0]
                nonce = candidate.tobytes('C').hex()
                thread_id = cand[1]
                submission_result = submit_share(thread_id=thread_id, address=pool_address,
                                                 nonce=nonce, block_hash=db_block_hash,
                                                 difficulty=diff, hashrate=total_hash_rate)
                if submission_result:
                    shares_submitted += 1

            while True:
                try:
                    stat = stats_queue.get(True, 0.001)
                    thread_id = stat[0]

                    if thread_id not in thread_hash_rate_history:
                        thread_hash_rate_history[thread_id] = list()

                    thread_hash_rate_history[thread_id].append(float(stat[2]))
                except Exception as e:
                    break

        except Exception as e:
            print("Main Thread hit an exception: {}".format(str(e)))
            import traceback
            traceback.print_exc(file=sys.stdout)
            pass
