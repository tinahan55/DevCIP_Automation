from lib.powerCycle import *
from lib.Device import *
import sys
import re
import logging
from lib.Tool import *
from time import gmtime, strftime

networktool = Network()
def set_log(filename,loggername):
    logpath = os.path.join(os.getcwd(), 'log')
    if not os.path.exists(logpath):
        os.makedirs(logpath)
    filepath = os.path.join(logpath, filename)
    logger = logging.getLogger(loggername)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh = logging.FileHandler(filepath)
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger

def device_check_info(logger,device,checkitem,checkcommand,checkmatch):
    title = "[%s][%s]"%(checkitem,checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand,5,checkmatch)
    logger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
    if checkresult== False:
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))

def  check_booting(hostip,check_cycle):
    k = 0
    while k < check_cycle:
        if networktool.Host_Ping(hostip):
            break
        else:
            time.sleep(1)
        k+=1
    return k

if __name__ == '__main__':
    logfilename = "coolboot%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"cool_boot")
    ip = "10.2.53.158"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    din_relay_ip = "10.2.53.199"
    din_relay_user ="root"
    din_relay_pwd ="lilee1234"
    din_relay_device_name = "R1-STS4"
    test_cycle = 20000
    power_cycle_sleep = 120
    checkcommandlist = ["show interface all"]
    checkitemlist = ["maintenance 0 (.*) up"]
    try:
        device =Device_Tool(ip,port,mode,username,password,"check_list")
        powerCycle = powerCycle()
        if device:
            device.device_get_version()
            logger.info("Device Bios Version:%s"%(device.bios_version))
            logger.info("Device recovery image:%s"%(device.boot_image))
            logger.info("Device build image:%s"%(device.build_image))
            for k in range(0, test_cycle):
                power_cycle_result =powerCycle.powerControl(din_relay_ip, din_relay_user, din_relay_pwd, din_relay_device_name )
                logger.info("[%s][power_cycle_result]result :%s"%(k,power_cycle_result))
                if power_cycle_result:
                    logger.info("[%s][power_cycle_sleep]%s seconds"%(k,power_cycle_sleep))
                    time.sleep(2)
                    count = check_booting(ip,power_cycle_sleep)
                    logger.info("[%s][power_cycle_sleep]wait %s seconds"%(k,count))
                    if count < power_cycle_sleep:
                        #time.sleep(power_cycle_sleep)
                        device =Device_Tool(ip,port,mode,username,password,"check_list")
                        if device:
                            checkitem = "device_check_interface_and_mobility"
                            logger.info("[%s]Starting"%(checkitem))
                            for index,value in enumerate(checkcommandlist):
                                checkmatch = checkitemlist[index]
                                device_check_info(logger,device,checkitem,value,checkmatch)

    except Exception,ex:
        logging.error("[coolboot]exception fail:%s "%(str(ex)))


