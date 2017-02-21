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

def Checking_PoE(device):
    checkitem ="Checking_PoE"
    device.device_send_command("show poe budget")
    vlan1_ip = "10.99.1.1"
    Meraki_ip = "10.99.1.110"
    logger.info("[%s]Starting- Ping IP CAM"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["show poe port 0","ping -c 10 -S %s %s"%(vlan1_ip,Meraki_ip)]
    checkitemlist = ["15.4","64 bytes from %s: icmp_seq=10 (.*)"%(Meraki_ip)]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

def Checking_Dialer(device):
    dialer0_index = 0
    dialer1_index = 1
    cellular_index = 0
    #dialer_carrier = "TWM"
    cellular0_usb_index="usb1"
    cellular1_usb_index = "usb2"

    checkitem ="Checking_Dialer"
    #device.device_send_command("Show PoE budget")

    logger.info("[%s]Starting- show interface all"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["show interface all","ping -I %s -c5 8.8.8.8"%(cellular0_usb_index),"ping -I %s -c5 8.8.8.8"%(cellular1_usb_index)]
    checkitemlist = ["dialer %s (.*) up | dialer %s (.*) up"%(dialer0_index,dialer1_index),"64 bytes from 8.8.8.8: icmp_seq=5 (.*)","64 bytes from 8.8.8.8: icmp_seq=5 (.*)"]
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)
        time.sleep(5)

def Checking_Tunnel(device):
    interfacelist = ['dialer 0', 'dialer 1','wlan 1']
    devicelist = ['usb1', 'usb2', 'wlan1']
    tunnel_control_server = "60.248.28.102"

   #times = 200000
   # for k in range(0, times):
    for index, value in enumerate(interfacelist):
            commanditem = "show mobility tunnel all"
            commandstatus = "%s (.*) UA" % (value)
            checkresult = device.device_send_command_match(commanditem, 7, commandstatus)
            logger.info("[%s]%s check %s result :%s" % (k, commandstatus, commanditem, checkresult))
            if checkresult == False:
                logger.info("[%s]%s check %s error :%s" % (k, commandstatus, commanditem, device.target_response))
                commanditem = "ping -I %s -c5 %s" % (devicelist[index], tunnel_control_server)
                commandstatus = "64 bytes from %s: icmp_seq=5 (.*)" % (tunnel_control_server)
                checkresult = device.device_send_command_match(commanditem, 7, commandstatus)
                logger.info("[%s]%s check %s result :%s" % (k, commandstatus, commanditem, checkresult))
                if checkresult == False:
                    logger.info("[%s]%s check %s error :%s" % (k, commandstatus, commanditem, device.target_response))
                    commanditem = "show interface all"
                    commandstatus = "%s (.*) up" % (value)
                    checkresult = device.device_send_command_match(commanditem, 7, commandstatus)
                    logger.info("[%s]%s check %s result :%s" % (k, commandstatus, commanditem, checkresult))
                    if checkresult == False:
                        logger.info("[%s]%s check %s error :%s" % (k, commandstatus, commanditem, device.target_response))

def Checking_Vlan(device):
    vlan1_index = 1
    vlan50_index = 50
    checkitem ="Checking_Vlan"
    Vlan1_ip="10.99.1.1"
    Vlan50_ip = "10.116.1.1 "

    logger.info("[%s]Starting- Ping Interface"%(checkitem))
    #device.device_send_command("config app-engine 0 disable")
    #time.sleep(30)
    checkcommandlist = ["show interface all","ping -S %s -c5 8.8.8.8"%(Vlan1_ip),"ping -S %s -c5 8.8.8.8"%(Vlan50_ip)]
    checkitemlist = ["vlan %s (.*) up | vlan %s (.*) up"%(vlan1_index,vlan50_index) ,"64 bytes from 8.8.8.8: icmp_seq=5 (.*)","64 bytes from 8.8.8.8: icmp_seq=5 (.*)"]
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

if __name__ == '__main__':
    logfilename = "Alpha%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"Alpha_Testing")
    ip ="10.2.53.190"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"Alpha_Testing")
    test_cycle = 20000
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")
        device.device_send_command("show version")


        for k in range(0, test_cycle):
            Checking_PoE(device)
            Checking_Dialer(device)
            Checking_Vlan(device)
            Checking_Tunnel(device)
            device.device_send_command("show version")
        #Reset_log(device)
        #Pretesting_Cellular(device)
        #Pretesting_Wifi(device)
        #Pretesting_Poe(device)
        #Pretesting_GPS(device
        #Checking_Tunnel(device)
