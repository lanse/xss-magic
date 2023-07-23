#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 11:22 PM
# @Author  : w8ay
# @File    : controller.py
import copy
import threading
import time
import traceback

from lib.core.common import dataToStdout
from lib.core.data import KB, logger, conf


def exception_handled_function(thread_function, args=()):
    try:
        thread_function(*args)
    except KeyboardInterrupt:
        KB["continue"] = False
        raise
    except Exception:
        traceback.print_exc()


def run_threads(num_threads, thread_function, args: tuple = ()):
    threads = []

    try:
        info_msg = "Staring [#{0}] threads".format(num_threads)#界面显示的线程数
        logger.info(info_msg)

        # Start the threads，num_threads默认是31个线程
        for num_threads in range(num_threads):
            thread = threading.Thread(target=exception_handled_function, name=str(num_threads),
                                      args=(thread_function, args))
            thread.setDaemon(True)#开启线程守护
            try:
                thread.start()
            except Exception as ex:
                err_msg = "error occurred while starting new thread ('{0}')".format(str(ex))
                logger.critical(err_msg)
                break

            threads.append(thread)

        # And wait for them to all finish
        alive = True
        while alive:#等候线程全部结束
            alive = False
            for thread in threads:
                if thread.is_alive():
                    alive = True
                    time.sleep(0.1)

    except KeyboardInterrupt as ex:
        KB['continue'] = False
        raise

    except Exception as ex:
        logger.error("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
        traceback.print_exc()
    finally:
        dataToStdout('\n')


def start():
    run_threads(conf.threads, task_run)


def task_run():#运行具体的payload
    
    while KB["continue"] or not KB["task_queue"].empty():
        poc_module_name, request, response = KB["task_queue"].get() #从线程队列里得到一条队列内容
       # logger.info(poc_module_name)
        KB.lock.acquire()
        KB.running += 1
        if poc_module_name not in KB.running_plugins:
            KB.running_plugins[poc_module_name] = 0
        KB.running_plugins[poc_module_name] += 1
        KB.lock.release()
       # printProgress() #底部右下角那个显示状态那行的内容
        #logger.info(KB["registered"])
        poc_module = copy.deepcopy(KB["registered"][poc_module_name])#把字典对应的装载的插件复制到poc里
        poc_module.execute(request, response) #这里直接去执行plugins.py的execute,因为plugins.py是插件的父类
        KB.lock.acquire()
        KB.finished += 1
        KB.running -= 1
        KB.running_plugins[poc_module_name] -= 1
        if KB.running_plugins[poc_module_name] == 0:
            del KB.running_plugins[poc_module_name]

        KB.lock.release()
       # printProgress()
   # printProgress()
    # TODO
    # set task delay


def printProgress():#输出右下角的信息
    KB.lock.acquire()
    if conf.debug:
        # 查看当前正在运行的插件
        KB.output.log(repr(KB.running_plugins))
    msg = '%d success | %d running | %d remaining | %s scanned in %.2f seconds' % (
        KB.output.count(), KB.running, KB.task_queue.qsize(), KB.finished, time.time() - KB.start_time)

    _ = '\r' + ' ' * (KB['console_width'][0] - len(msg)) + msg
    dataToStdout(_)
    KB.lock.release()


def task_push(plugin_type, request, response):#调用目录下的插件
    
    for _ in KB["registered"].keys():
        module = KB["registered"][_]
        # logger.info("start......")
        # logger.info(KB["registered"][_])
        # logger.info(module.type)
        # logger.info("end......")
        if module.type == plugin_type:#通过这里拒绝loader主插件，因为他的类型是scanner，各个插件类型对应各自所在的目录，这里传入的类型必须与目录一致才能执行
            KB['task_queue'].put((_, copy.deepcopy(request), copy.deepcopy(response)))


def task_push_from_name(pluginName, req, resp):
    #把需要检测的地址放入task_queue的队列里，KB['task_queue']对应的是Queue()队列，put方法就是放入队列
    KB['task_queue'].put((pluginName, copy.deepcopy(req), copy.deepcopy(resp)))
    
    
