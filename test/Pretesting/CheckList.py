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
    logfilename = "CheckList%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"check_list")
    ip ="10.2.52.53"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"check_list")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        logger.info("Disable App Engine to wait 30 seconds")

        device.device_send_command("config app-engine 0 enable")
        time.sleep(30)
        device.device_send_command("config app-engine 0 disable")
        time.sleep(30)


        checkitem = "device_check_cellular"
        checkcommandlist = ["slotmapping -l","slotmapping -l","show line cellular all"]
        checkitemlist = ["usb1","usb2","cellular (.*) 0"]
        logger.info("[%s]Starting"%(checkitem))
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device,checkitem,value,checkmatch)


        checkitem = "device_check_wifi"
        checkcommandlist = ["ifconfig -a","ifconfig -a"]
        checkitemlist = ["wlan0","wlan1"]
        logger.info("[%s]Starting"%(checkitem))
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device,checkitem,value,checkmatch)


        checkitem ="check_service_status"
        checkcommandlist = ["show service all","show service all","show service all","show service all"]
        checkitemlist = ["fcapsd (.*) Started ","platformd (.*) Started","imgupd_updater (.*) Started","gpsd (.*) Started"]
        logger.info("[%s]Starting"%(checkitem))
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device,checkitem,value,checkmatch)


        checkitem="check_disk_status"
        checkcommandlist=["cat /proc/partitions","cat /proc/partitions","cat /proc/partitions"]
        checkitemlist = ["sda","sdb","sdc"]
        logger.info("[%s]Starting"%(checkitem))
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device,checkitem,value,checkmatch)

        checkitem="check_odb2_status"
        checkcommandlist=["hexdump /dev/ttyS3"]
        checkitemlist = ["1710"]
        logger.info("[%s]Starting"%(checkitem))
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device,checkitem,value,checkmatch)
















