#!/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : start.py
import random
import time
import json
import traceback
import pickle
from multiprocessing import Process
from myscan.lib.core.common import getredis
from myscan.lib.core.data import logger, cmd_line_options
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.core.common import get_random_str, get_random_num
from myscan.pocs.search import searchmsg
from myscan.lib.core.pythonpoc import python_poc
from myscan.lib.core.block_info import block_info
from myscan.lib.core.plugin import plugin
from myscan.config import scan_set
import signal


def handler(signum, frame):
    # raise AssertionError
    logger.warning("run_python timeout")


def run_python():
    red = getredis()
    try:
        while True:
            try:
                if scan_set.get("random_test", False):
                    workdata = red.spop("work_data_py_set")
                else:
                    # red.lpush("work_data_py", pickledata)
                    workdata = red.lpop("work_data_py")

                if workdata:
                    workdata_ = pickle.loads(workdata)
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(int(scan_set.get("poc_timeout")))

                    # workdata_ will like this
                    # {
                    #     "id": id,
                    #     "data": None,  perscheme 为None
                    #     "poc": poc,
                    #     "type": "perscheme"
                    # }
                    logger.debug("Python poc get one data, type:" + workdata_.get("type"))
                    p = python_poc(workdata_)
                    p.run()
                    signal.alarm(0)
                else:
                    time.sleep(random.uniform(1, 2))
            except Exception as ex:
                traceback.print_exc()
                logger.warning("Run_python scan get error:{}".format(ex))
                pass
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")
    except Exception as ex:
        traceback.print_exc()
        logger.warning("Run_python main scan get error:{}".format(ex))


def process_start():
    try:
        work_process = []
        try:

            logger.info("Python Script use {} process".format(cmd_line_options.process))
            logger.info("Some scan use {} threads ".format(cmd_line_options.threads))

            for x in range(cmd_line_options.process):
                work2 = Process(target=run_python)
                work_process.append(work2)
            for p in work_process:
                p.daemon = True
                p.start()
        except Exception as ex:
            traceback.print_exc()
            err_msg = "Error occurred while starting new scan ('{0}')".format(str(ex))
            logger.warning(err_msg)
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")


def start():
    logger.info("Myscan Python Moudle Listen ...")
    red = getredis()
    try:
        while True:
            try:
                if cmd_line_options.command == "webscan":
                    data = red.rpop("burpdata")
                    if data:
                        red.hincrby("count_all", "doned", amount=1)
                        logger.debug("Get one data from burpdata")
                        dictdata = None
                        try:
                            dictdata = json.loads(data)
                        except Exception as ex:
                            logger.warning("Process burpdata to json get error:" + str(ex))
                            continue
                        if dictdata is not None:
                            # 开启plugin
                            if cmd_line_options.plugins:
                                plugin(dictdata)
                            if "all" in cmd_line_options.disable:
                                continue
                            # dictdata.get("filter")决定是否过滤，burp的proxy传过来为true，右键发过来为false
                            is_filter = dictdata.get("filter")
                            host = dictdata.get("url").get("host")
                            port = dictdata.get("url").get("port")
                            block = block_info(host, port)
                            if allow_host(host) and not block.is_block():
                                # 是否启动被动搜索模式
                                if scan_set.get("search_open", False):
                                    s = searchmsg(dictdata)
                                    s.verify()
                                    # s.saveresult()
                                # 把dictdata分配一个id
                                id = get_random_str(10) + str(get_random_num(5))

                                toredisdatas = []
                                data_parser = dictdata_parser(dictdata)
                                # perfile
                                if cmd_line_options.pocs_perfile:
                                    if not is_filter or not data_parser.is_perfile_doned():
                                        logger.debug(
                                            data_parser.getperfile().capitalize() + " is_perfile_doned res:False")
                                        for poc in cmd_line_options.pocs_perfile:
                                            toredisdatas.append(
                                                ("work_data_py", pickle.dumps({
                                                    "id": id,
                                                    "data": data_parser.getperfile(),
                                                    "poc": poc,
                                                    "type": "perfile"
                                                }))
                                            )
                                    else:
                                        logger.debug(
                                            data_parser.getperfile().capitalize() + " is_perfile_doned res:True")
                                # perfolder
                                if cmd_line_options.pocs_perfoler:
                                    if not is_filter:
                                        # 通过一个url获取其对应的所有目录
                                        folders = data_parser.getperfolders()
                                    else:
                                        folders = data_parser.is_perfolder_doned()

                                    if folders != []:
                                        for folder in folders:
                                            for poc in cmd_line_options.pocs_perfoler:
                                                # red.lpush("work_data_py", pickle.dumps({
                                                #     "data": folder,
                                                #     "dictdata": dictdata,
                                                #     "type": "perfolder"
                                                # }))
                                                toredisdatas.append(("work_data_py", pickle.dumps({
                                                    "id": id,
                                                    "data": folder,
                                                    "poc": poc,
                                                    "type": "perfolder"
                                                })))
                                # scheme
                                if cmd_line_options.pocs_perscheme:
                                    if not is_filter or not data_parser.is_perscheme_doned():
                                        logger.debug(
                                            data_parser.getperfile().capitalize() + " is_perscheme_doned res:False")
                                        for poc in cmd_line_options.pocs_perscheme:
                                            toredisdatas.append(("work_data_py", pickle.dumps({
                                                "id": id,
                                                "data": None,  # 这里没有data字段，无关data字段了
                                                "poc": poc,
                                                "type": "perscheme"
                                            })))
                                    else:
                                        logger.debug(
                                            data_parser.getperfile().capitalize() + " is_perscheme_doned res:True")
                                # 分发

                                if toredisdatas:
                                    # 给id新建一个hash
                                    red.hmset(id, {'data': data, 'count': len(toredisdatas)})
                                    for key, pickledata in toredisdatas:
                                        if scan_set.get("random_test", False):
                                            red.sadd("work_data_py_set", pickledata)
                                        else:
                                            red.lpush("work_data_py", pickledata)
                            else:
                                logger.debug("Host block:" + host)
                    else:
                        time.sleep(random.uniform(0, 1))
                elif cmd_line_options.command == "hostscan":
                    data = red.rpop("hostdata")
                    if data:
                        red.hincrby("count_all", "doned", amount=1)
                        logger.debug("Get one data from hostdata")
                        dictdata = None
                        try:
                            dictdata = json.loads(data)
                        except Exception as ex:
                            logger.warning("Process hostdata to json get error:" + str(ex))
                            continue
                        if dictdata is not None:
                            # 开启plugin
                            if cmd_line_options.plugins:
                                plugin(dictdata)
                            if "all" in cmd_line_options.disable:
                                continue
                            is_filter = dictdata.get("filter")
                            host = dictdata.get("addr")
                            port = dictdata.get("port")
                            block = block_info(host, port)
                            id = get_random_str(10) + str(get_random_num(5))
                            if allow_host(host):
                                toredisdatas = []
                                if is_filter:
                                    if not block.is_block():
                                        block.block_it()
                                    else:
                                        continue
                                for poc in cmd_line_options.pocs_perserver:
                                    toredisdatas.append(pickle.dumps({
                                        "id": id,
                                        "data": None,  # 这里没有data字段，无关data字段了
                                        "poc": poc,
                                        "type": "perserver"
                                    }))
                                if toredisdatas:
                                    red.hmset(id, {'data': data, 'count': len(toredisdatas)})
                                red.hmset(id, {'data': data, 'count': len(toredisdatas)})
                                for pickledata in toredisdatas:
                                    if scan_set.get("random_test", False):
                                        red.sadd("work_data_py_set", pickledata)
                                    else:
                                        red.lpush("work_data_py", pickledata)
                    else:
                        time.sleep(random.uniform(1, 2))




            except Exception as ex:
                logger.debug("Run start get error:{}".format(ex))
                traceback.print_exc()
                continue
    except KeyboardInterrupt as ex:
        logger.warning("Ctrl+C was pressed ,aborted program")


def allow_host(host):
    allow_flag = 0
    if not is_in_dishost(host):
        if not cmd_line_options.host:
            allow_flag = 1
        else:
            # if host in cmd_line_options.host:
            for x in cmd_line_options.host:
                if x in host:
                    allow_flag = 1
                    break
        if allow_flag:
            return True
        return False
    else:
        return False


def is_in_dishost(host):
    for x in cmd_line_options.dishost:
        if x in host:
            return True
