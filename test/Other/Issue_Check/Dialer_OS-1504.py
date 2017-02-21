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


def Pretesting_Appengine(device):
    checkitem ="Pretesting_Appengine"
    device.device_send_command("config app-engine 0 description SQA")

    logger.info("[%s]Starting- app engine stop"%(checkitem))
    device.device_send_command("config app-engine 0 disable")
    time.sleep(30)
    checkcommandlist = ["show app-engine 0 info"]
    checkitemlist = ["Administrative : Power Off | Operational : Not Running | Description : SQA"]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

    logger.info("[%s]Starting- app engine start"%(checkitem))
    device.device_send_command("config app-engine 0 enable")
    time.sleep(30)
    checkcommandlist = ["show app-engine 0 info"]
    checkitemlist = ["Administrative : Power On | Operational : Running | Description : SQA"]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

def Pretesting_Tunnel(device):
    checkitem ="Pretesting_Tunnel"
    logger.info("[%s]Shutdown Tunnel via disable eth0 on LMC"%(checkitem))
    device.device_send_command("no config interface eth 2 enable")
    checkcommandlist = ["show interface all"]
    checkitemlist = ["eth 2 | 60.248.28.100 | disable | down"]
    time.sleep(3)
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
    time.sleep(720)

    logger.info("[%s]Turn On Tunnel via enable eth0 on LMC"%(checkitem))
    device.device_send_command("config interface eth 2 enable")
    checkcommandlist = ["show interface all"]
    checkitemlist = ["eth 2 | 60.248.28.100 | enable | up"]
    time.sleep(3)
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
    time.sleep(600)

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
    logfilename = "Pretesting%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"Pre_Testing")
    ip ="10.2.11.62"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="Lilee1234"
    device =Device_Tool(ip,port,mode,username,password,"Pre_Testing")
    test_cycle = 3000
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")


        #Pretesting_Cellular(device)

        #Pretesting_Wifi(device)


        #Pretesting_Poe(device)

        #Pretesting_GPS(device)
        for k in range(0, test_cycle):
            Pretesting_Tunnel(device)