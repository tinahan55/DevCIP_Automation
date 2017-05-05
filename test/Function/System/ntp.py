from lib.Device import *
from lib.Configuration import *
import logging
import os
import sys
from time import gmtime, strftime



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




logfilename = "ntp%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
logger = set_log(logfilename,"ntp_testing")

if __name__ == '__main__':
    ip ="192.168.11.114"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"ntp_testing")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")

        ntp_server_list = ["118.163.81.61","216.239.32.15"]
        ntp_server_prority_list = ["0","1"]
        time_source ='external'

        for ntp_server in ntp_server_list:
            device.device_set_lilee_mode =True
            checkcommand = "ping %s"%(ntp_server)
            checkmatch = "64 bytes from %s: icmp_seq=(.*)"%(ntp_server)
            checkresult = device.device_send_command_match(checkcommand,7,checkmatch)
            logger.info("check ntp server %s result :%s"%(ntp_server,checkresult))
            device.device_send_command("\x03")

            if checkresult ==False:
                sys.exit(0)

        configlist = list()
        function = Function("ntp")
        configlist.extend(function.get_ntp(ntp_server_list,ntp_server_prority_list,time_source))
        configlist.extend(function.get_service("ntp"))


        device.device_set_no_config(configlist)

        device.device_set_configs(configlist)

        time.sleep(60)

        checkcommandlist =["show time source","show ntp server","show ntp status"]
        checkitemlist = ["Source : ntp","118.163.81.61 | 216.239.32.15","NTP Status : sync to NTP server (.*)"]

        checkitem = "check ntp status"
        logger.info("[%s]Starting"%(checkitem))
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device,checkitem,value,checkmatch)













