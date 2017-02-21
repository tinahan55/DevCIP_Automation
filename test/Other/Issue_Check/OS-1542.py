from lib.Device import *
from lib.Configuration import *
import logging
import os
from time import gmtime, strftime


def device_check_info(logger,device,checkitem,checkcommand,checkmatch):
    title = "[%s][%s]"%(checkitem,checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand,5,checkmatch)
    logger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
    if checkresult== False:
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))

def Checking_Var_log(device):
    Volume = "df -h"
    Task_Fcapsd = "ps aux" + "|" + "grep fcapsd"
    Task_All = "ps aux"

    checkitem ="Checking_Var_log"
    device.device_send_command("ps aux")
    logger.info("[%s]Starting- getting PS AUX end\\n %s" % (checkitem, device.target_response))


    logger.info("[%s]Starting- getting status start"%(checkitem))
    #device.device_send_command("config app-engine 0 enable")
    checkcommandlist = ["%s"%(Volume),"%s"%(Task_Fcapsd),"%s"%(Task_All)]
    checkitemlist = ["mmcblk0p9 | 100% | log","Ssl | fcapsd | fcapsd_watchdg","kworker"]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
    logger.info("[%s]Starting- getting PS AUX start" % (checkitem))


    time.sleep(60)
    logger.info("[%s]Starting- getting status start" % (checkitem))
    checkcommandlist = ["%s"%(Volume),"%s"%(Task_Fcapsd),"%s"%(Task_All)]
    checkitemlist = ["mmcblk0p9 | 100% | log","Ssl | fcapsd | fcapsd_watchdg","kworker"]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
    time.sleep(60)

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

if __name__ == '__main__':
    logfilename = "System%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"System_Testing")
    ip ="10.2.53.151"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"USB")

    test_cycle = 20000
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")

        #Pretesting_Appengine_with_USB(device)


        for k in range(0, test_cycle):
            Checking_Var_log(device)