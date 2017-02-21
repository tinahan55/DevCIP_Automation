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
    return checkresult


def Checking_PoE(device):
    checkitem ="Checking_PoE"
    vlan10_ip = "192.168.10.1"
    IP_CAM_ip = "192.168.10.99"
    logger.info("[%s]Starting- Ping IP CAM"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["show poe port 0","ping -c 10 -S %s %s"%(vlan10_ip,IP_CAM_ip)]
    checkitemlist = ["0 | 2 | n/a | 7.0","64 bytes from %s: icmp_seq=10 (.*)"%(IP_CAM_ip)]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

def Checking_Dialer(device):
    dialer0_index = 0
    dialer1_index = 1
    cellular_index = 0
    #dialer_carrier = "TWM"
    WAN_ip = "8.8.8.8"
    cellular0_usb_index="usb1"
    cellular1_usb_index = "usb2"

    checkitem ="Checking_Dialer"
    #device.device_send_command("Show PoE budget")

    logger.info("[%s]Starting- show interface all"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["show interface all","ping -I %s -c5 %s"%(cellular0_usb_index,WAN_ip ),"ping -I %s -c5 %s"%(cellular1_usb_index,WAN_ip )]
    checkitemlist = ["dialer %s (.*) up | dialer %s (.*) up"%(dialer0_index,dialer1_index),"64 bytes from %s: icmp_seq=5 (.*)"%(WAN_ip),"64 bytes from %s: icmp_seq=5 (.*)"%(WAN_ip)]


    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

def Checking_Vlan(device):
    vlan10_index = 10
    vlan30_index = 30
    WAN_ip = "8.8.8.8"
    checkitem ="Checking_Vlan"
    AppEngine_vlan10_ip="192.168.10.161"
    AppEngine_vlan30_ip = "192.168.30.161"
    IP_CAM_ip="192.168.10.99"

    logger.info("[%s]Starting- Ping Interface"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["show interface all","ping -S %s -c5 %s"%(AppEngine_vlan10_ip,IP_CAM_ip),"ping -S %s -c5 %s"%(AppEngine_vlan30_ip,WAN_ip)]
    checkitemlist = ["vlan %s (.*) up | vlan %s (.*) up"%(vlan10_index,vlan30_index) ,"64 bytes from %s: icmp_seq=5 (.*)"%(IP_CAM_ip),"64 bytes from %s: icmp_seq=5 (.*)"%(WAN_ip)]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

def Reset_log(device):
    #dialer0_index = 0
    #dialer1_index = 1
    cellular_index = 0
    #dialer_carrier = "TWM"
    #cellular0_usb_index="usb1"
    #cellular1_usb_index = "usb2"

    checkitem ="Reset_log"
    #device.device_send_command("Show PoE budget")

    logger.info("[%s]Starting- Reset Log"%(checkitem))
    #device.device_send_command("show ntp status")
    #time.sleep(30)
    checkcommandlist = ["show ntp status","ll /var/log/cores/","diag syslog database reset","y"]
    checkitemlist = ["sync to NTP server" ,"total 0","All log will be removed. Are you sure you want to continue (y/n)?","The database is reset."]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

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

def Checking_WDU_Vlan(device):
    vlan20_index = 20
    vlan50_index = 50
    #checkitem = "Checking_WDU_Vlan"
    WDU_vlan20_ip = "10.16.1.153"
    WDU_vlan50_ip = "10.116.3.45"

    checkitem ="Checking_WDU_Vlan"
    #device.device_send_command("Show PoE budget")

    logger.info("[%s] Starting- Checking WDU"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["ifconfig br0.%s"%(vlan20_index),"ifconfig br0.%s"%(vlan50_index),"show mobility tunnel all","show mobility tunnel all","ping -S %s -c5 8.8.8.8"%(WDU_vlan20_ip),"ping -S %s -c5 8.8.8.8"%(WDU_vlan50_ip),"ping -S %s -c5 10.116.3.254"%(WDU_vlan20_ip)]
    checkitemlist = ["br0.20 | flags=4163<UP,BROADCAST,RUNNING |inet %s | "%(WDU_vlan20_ip),"br0.50 | flags=4163<UP,BROADCAST,RUNNING | inet %s"%(WDU_vlan50_ip),"dialer 0 | UA","dialer 1 | UA","64 bytes from 8.8.8.8: icmp_seq=5 (.*)","64 bytes from 8.8.8.8: icmp_seq=5 (.*)","64 bytes from 10.116.3.254: icmp_seq=5 (.*)"]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

if __name__ == '__main__':
    logfilename = "Pretesting%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"Presidio_Testing")
    ip ="10.2.53.161"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"Presidio_Testing")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")

        #Reset_log(device)
        #Pretesting_Cellular(device)
        #Pretesting_Wifi(device)
        #Pretesting_Poe(device)
        #Pretesting_GPS(device)
        Checking_PoE(device)
        Checking_Dialer(device)
        Checking_Vlan(device)
        Checking_WDU_Vlan(device)
