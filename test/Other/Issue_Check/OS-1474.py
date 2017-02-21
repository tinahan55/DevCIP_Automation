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

def Pretesting_Appengine_with_USB(device):
    USB_VENDOR = "Samsung"
    USB_MODEL = "Storage"
    USB_TRAN = "usb"
    checkitem ="USB_mount"
    device.device_send_command("show version")

    logger.info("[%s,%s]Starting- app engine stop"%(checkitem,k))
    device.device_send_command("config app-engine 0 disable")
    time.sleep(60)
    checkcommandlist = ["lsblk -S"]
    checkitemlist = ["%s | %s | %s"%(USB_VENDOR,USB_MODEL,USB_TRAN)]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

    logger.info("[%s]Starting- app engine start"%(checkitem))
    device.device_send_command("config app-engine 0 enable")
    time.sleep(30)
    checkcommandlist = ["lsblk -S"]
    checkitemlist = ["%s | %s | %s"%(USB_VENDOR,USB_MODEL,USB_TRAN)]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

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
    ip ="10.2.53.158"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"Pre_Testing")
    test_cycle = 2000
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")

        #Pretesting_Appengine_with_USB(device)


        for k in range(0, test_cycle):
            Pretesting_Appengine_with_USB(device)
