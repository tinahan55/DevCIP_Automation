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

def Pretesting_Cellular(device):
    configlist = list()
    profile0_name ="cht"
    access0_name = "internet"
    dialer0_index = 0
    cellular0_index = 0
    dialer0_carrier = "Chunghwa"
    cellular0_usb_index="usb1"

    profile1_name ="twe"
    access1_name="internet"
    dialer1_index =1
    cellular1_index = 1
    dialer1_carrier="TWM"
    cellular1_usb_index="usb2"


    profile = Profile("Celluar")
    configlist.extend(profile.get_cellular_profile(profile0_name,access0_name))
    configlist.extend(profile.get_cellular_profile(profile1_name,access1_name))

    interface = Interface("Celluar")
    configlist.extend(interface.get_dialer_interface(dialer0_index,profile0_name,cellular0_index))
    configlist.extend(interface.get_dialer_interface(dialer1_index,profile1_name,cellular1_index))
    device.device_set_configs(configlist)
    time.sleep(30)

    checkitem ="Pretesting_Cellular"
    checkcommandlist = ["show cellular-profile %s"%(profile0_name),"show platform led","show interface all","show interface dialer %s detail"%(dialer0_index),"show sim-management current-status"
        ,"ping -I %s -c5 8.8.8.8"%(cellular0_usb_index)]

    checkitemlist = ["Access Point Name (.*) %s"%(access0_name) ,"LTE%s (.*) green"%(cellular0_index),"dialer %s (.*) up"%(dialer0_index)
       ,"Operational : up | MTU : 1500","dialer %s (.*) %s (.*)"%(dialer0_index,dialer0_carrier),"64 bytes from 8.8.8.8: icmp_seq=5 (.*)"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)


    checkcommandlist = ["show cellular-profile %s"%(profile1_name),"show platform led","show interface all","show interface dialer %s detail"%(dialer1_index),"show sim-management current-status"
        ,"ping -I %s -c5 8.8.8.8"%(cellular1_usb_index)]

    checkitemlist = ["Access Point Name (.*) %s"%(access1_name) ,"LTE%s (.*) green"%(cellular1_index),"dialer %s (.*) up"%(dialer1_index)
       ,"Operational : up | MTU : 1500","dialer %s (.*) %s (.*)"%(dialer1_index,dialer1_carrier),"64 bytes from 8.8.8.8: icmp_seq=5 (.*)"]

    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

def Pretesting_Wifi(device):
    configlist = list()
    ap_profile_name ="ap-profile"
    sta_profile_name ="eap-peap"
    ap_ssid_name = "auto-testing"
    sta_ssid_name ="SQA-STA-EAP-2.4G"
    wlan0_index = 0
    wlan0_mode = "ap"
    wlan0_ip_mode ="static"
    wlan0_ip_address = "192.168.11.1"
    wlan1_index = 1
    wlan1_mode = "sta"
    wlan1_ip_mode="dhcp"


    #### wpa-psk setting
    ap_key_type = "wpa-psk"
    ap_wpa_version = "auto"
    ap_wpa_key="lilee~1234"

    #### wpa-eap setting.
    sta_key_type = "wpa-eap"
    sta_wpa_version = "2"
    sta_auth_type ="sta-eap"
    sta_eap_type ="peap"
    sta_eap_identity ="lance"
    sta_eap_password = "lance0124"


    profile = Profile("Wifi")
    configlist.extend(profile.get_wifi_profile(ap_profile_name,ap_ssid_name,ap_key_type,ap_wpa_version,ap_wpa_key))

    interface = Interface("wifi")
    configlist.extend(interface.get_wifi_interface(wlan0_index,ap_profile_name,wlan0_mode,wlan0_ip_mode))
    device.device_set_configs(configlist)

    checkitem ="Pretesting_Wifi_AP"

    checkcommandlist = ["show wifi-profile %s"%(ap_profile_name),"show platform led","show interface all"
        ,"show interface wlan %s detail"%(wlan0_index)]
    checkitemlist = ["SSID : %s | WPA PSK : WPA PSK"%(ap_ssid_name),"WLAN%s (.*) green"%(wlan0_index),"wlan %s (.*) %s (.*) up"%(wlan0_index,wlan0_ip_address)
        ,"Operational : up | MTU : 1500"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)


    profile = Profile("Wifi")
    configlist.extend(profile.get_wifi_profile(sta_profile_name,sta_ssid_name,sta_key_type
                                               ,sta_wpa_version,"",sta_auth_type))

    interface = Interface("wifi")
    configlist.extend(interface.get_wifi_interface(wlan1_index,sta_profile_name,wlan1_mode,wlan1_ip_mode))
    device.device_set_configs(configlist)

    checkitem ="Pretesting_Wifi_Station"

    checkcommandlist = ["show wifi-profile %s"%(sta_profile_name),"show platform led","show interface all"
        ,"show interface wlan %s detail"%(wlan0_index)]
    checkitemlist = ["SSID : %s | WPA PSK : %s"%(ap_ssid_name,sta_key_type),"WLAN%s (.*) green"%(wlan1_index),"wlan %s (.*) up"%(wlan1_index)
        ,"Operational : up | MTU : 1500"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

def Pretesting_Poe(device):

    checkitem ="Pretesting_Poe"
    checkcommandlist = ["show poe budget"]

    checkitemlist = ["Oper. Limit: 61.6 watts"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

def Pretesting_GPS(device):

    checkitem ="Pretesting_GPS"
    checkcommandlist = ["show gps detail"]

    checkitemlist = ["Fix Quality : 3D | Latitude : 25(.*) | Longitude : 121(.*)"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

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
    ip ="10.2.52.54"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"Pre_Testing")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")

        Pretesting_Cellular(device)

        Pretesting_Wifi(device)

        Pretesting_Poe(device)

        Pretesting_GPS(device)

        Pretesting_Appengine(device)

