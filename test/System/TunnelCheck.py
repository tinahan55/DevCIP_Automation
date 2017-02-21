from lib.Device import *
import logging
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



if __name__ == '__main__':
    logfilename = "TunnelCheck%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"check_list")
    ip ="10.2.52.54"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"tunnel_check")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        interfacelist = ['dialer 0','dialer 1']
        devicelist = ['usb1','usb2']
        tunnel_control_server ="60.248.28.118"

        times = 200000
        for k in range(0, times):
            for index,value in enumerate(interfacelist):
                commanditem = "show mobility tunnel all"
                commandstatus ="%s (.*) UA"%(value)
                checkresult = device.device_send_command_match(commanditem,7,commandstatus)
                logger.info("[%s]%s check %s result :%s"%(k,commandstatus,commanditem,checkresult))
                if checkresult == False:
                    logger.info("[%s]%s check %s error :%s"%(k,commandstatus,commanditem,device.target_response))
                    commanditem = "ping -I %s -c5 %s"%(devicelist[index],tunnel_control_server)
                    commandstatus = "64 bytes from %s: icmp_seq=5 (.*)"%(tunnel_control_server)
                    checkresult = device.device_send_command_match(commanditem,7,commandstatus)
                    logger.info("[%s]%s check %s result :%s"%(k,commandstatus,commanditem,checkresult))
                    if checkresult ==False:
                        logger.info("[%s]%s check %s error :%s"%(k,commandstatus,commanditem,device.target_response))
                        commanditem = "show interface all"
                        commandstatus ="%s (.*) up"%(value)
                        checkresult = device.device_send_command_match(commanditem,7,commandstatus)
                        logger.info("[%s]%s check %s result :%s"%(k,commandstatus,commanditem,checkresult))













