__author__ = 'lance'
from lib.powerCycle import *
from lib.Device import *
import sys
import re
import logging
from lib.Tool import *
from time import gmtime, strftime

networktool = Network()
mainlogger = Log("NPI", "NPI")


def device_check_info(mainlogger,device,checkitem,checkcommand,checkmatch):
    try:
        title = "[%s][%s]"%(checkitem,checkcommand)
        mainlogger.info("%s starting"%(title))
        checkresult = device.device_send_command_match(checkcommand,7,checkmatch)
        mainlogger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
        if checkresult == True:
            result = "Passed"
        else:
            result = "Failed"
            mainlogger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def  check_booting(hostip,check_cycle):
    k = 0
    while k < check_cycle:
        if networktool.Host_Ping(hostip,30):
            break
        else:
            time.sleep(1)
        k+=1
    return k

def Checking_Wifi_1020(device):
    configlist = list()
    ap_profile_name ="NPI"
    sta_profile_name ="Jess"
    ap_ssid_name = "NPI-1020"
    sta_ssid_name ="SJ-STS-Alpha"
    wlan0_index = 0
    wlan0_mode = "ap"
    wlan0_ip_mode ="static"
    wlan0_ip_address = "158.168.11.1"
    wlan1_index = 1
    wlan1_mode = "sta"
    wlan1_ip_mode="dhcp"


    #### wpa-psk setting
    ap_key_type = "wpa-psk"
    ap_wpa_version = "auto"
    ap_wpa_key="Lilee~1234"
    sta_wpa_key="ilovelilee"

    #### wpa-eap setting.
    sta_key_type = "wpa-psk"
    sta_wpa_version = "2"
    sta_auth_type ="sta-eap"
    sta_eap_type ="peap"
    sta_eap_identity ="lance"
    sta_eap_password = "lance0124"


    #profile = Profile("Wifi")
    #configlist.extend(profile.get_wifi_profile(ap_profile_name,ap_ssid_name,ap_key_type,ap_wpa_version,ap_wpa_key))

    #interface = Interface("wifi")
    #configlist.extend(interface.get_wifi_interface(wlan0_index,ap_profile_name,wlan0_mode,wlan0_ip_mode))
    #device.device_set_configs(configlist)

    checkitem ="Checking_Wifi_AP"

    checkcommandlist = ["show wifi-profile %s"%(ap_profile_name),"show platform led","show interface all"
        ,"show interface wlan %s detail"%(wlan0_index)]
    checkitemlist = ["SSID : %s | WPA PSK : %s"%(ap_ssid_name,ap_wpa_key),"WLAN%s (.*) amber"%(wlan0_index),"wlan %s (.*) %s (.*) up"%(wlan0_index,wlan0_ip_address)
        ,"Operational : up | MTU : 1500"]

    mainlogger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(mainlogger,device,checkitem,value,checkmatch)


    #profile = Profile("Wifi")
    #configlist.extend(profile.get_wifi_profile(sta_profile_name,sta_ssid_name,sta_key_type,sta_wpa_version,"",sta_auth_type))

    #interface = Interface("wifi")
    #configlist.extend(interface.get_wifi_interface(wlan1_index,sta_profile_name,wlan1_mode,wlan1_ip_mode))
    #device.device_set_configs(configlist)

    checkitem ="Checking_Wifi_Station"

    checkcommandlist = ["show wifi-profile %s"%(sta_profile_name),"show platform led","show interface all"
        ,"show interface wlan %s detail"%(wlan1_index)]
    checkitemlist = ["SSID : %s | WPA PSK : %s"%(sta_ssid_name,sta_wpa_key),"WLAN%s (.*) amber"%(wlan1_index),"wlan %s (.*) up"%(wlan1_index)
        ,"Operational : up | MTU : 1500"]

    mainlogger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(mainlogger,device,checkitem,value,checkmatch)

def Checking_Wifi_1010(device):
    configlist = list()
    ap_profile_name ="NPI"
    sta_profile_name ="Jess"
    ap_ssid_name = "NPI-1010"
    sta_ssid_name ="SJ-STS-Alpha"
    wlan0_index = 0
    wlan0_mode = "ap"
    wlan0_ip_mode ="static"
    wlan0_ip_address = "163.168.11.1"
    wlan1_index = 1
    wlan1_mode = "sta"
    wlan1_ip_mode="dhcp"


    #### wpa-psk setting
    ap_key_type = "wpa-psk"
    ap_wpa_version = "auto"
    ap_wpa_key="Lilee~1234"
    sta_wpa_key= "ilovelilee"

    #### wpa-eap setting.
    sta_key_type = "wpa-psk"
    sta_wpa_version = "2"
    sta_auth_type ="sta-eap"
    sta_eap_type ="peap"
    sta_eap_identity ="lance"
    sta_eap_password = "lance0124"


    #profile = Profile("Wifi")
    #configlist.extend(profile.get_wifi_profile(ap_profile_name,ap_ssid_name,ap_key_type,ap_wpa_version,ap_wpa_key))

    #interface = Interface("wifi")
    #configlist.extend(interface.get_wifi_interface(wlan0_index,ap_profile_name,wlan0_mode,wlan0_ip_mode))
    #device.device_set_configs(configlist)

    checkitem ="Checking_Wifi_AP"

    checkcommandlist = ["show wifi-profile %s"%(ap_profile_name),"show platform led","show interface all"
        ,"show interface wlan %s detail"%(wlan0_index)]
    checkitemlist = ["SSID : %s | WPA PSK : %s"%(ap_ssid_name,ap_wpa_key),"WLAN%s (.*) amber"%(wlan0_index),"wlan %s (.*) %s (.*) up"%(wlan0_index,wlan0_ip_address),"Operational : up | MTU : 1500"]

    mainlogger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(mainlogger,device,checkitem,value,checkmatch)


    #profile = Profile("Wifi")
    #configlist.extend(profile.get_wifi_profile(sta_profile_name,sta_ssid_name,sta_key_type,sta_wpa_version,"",sta_auth_type))

    #interface = Interface("wifi")
    #configlist.extend(interface.get_wifi_interface(wlan1_index,sta_profile_name,wlan1_mode,wlan1_ip_mode))
    #device.device_set_configs(configlist)

    checkitem ="Checking_Wifi_Station"

    checkcommandlist = ["show wifi-profile %s"%(sta_profile_name),"show platform led","show interface all","show interface wlan %s detail"%(wlan1_index)]
    checkitemlist = ["SSID : %s | WPA PSK : %s"%(sta_ssid_name,sta_wpa_key),"WLAN%s (.*) amber"%(wlan1_index),"wlan %s (.*) up"%(wlan1_index),"Operational : up | MTU : 1500"]

    mainlogger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(mainlogger,device,checkitem,value,checkmatch)

def Checking_GPS(device):
    try:
        GPS_index = "/dev/ttyUSB1"
        checkitem ="Checking_GPS"
        #device.device_send_command("Show PoE budget")

        mainlogger.info("[%s] Starting- Checking_GPS"%(checkitem))
        #device.device_send_command("config app-engine 0 disable")
        #time.sleep(30)
        checkcommandlist = ["slotmapping -l","show gps detail"]
        checkitemlist = ["GPS(.*)ttyUSB1","Fix Quality : 3D"]
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(mainlogger,device,checkitem,value,checkmatch)
            time.sleep(5)
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def Checking_PoE(device):
    try:
        checkitem ="Checking_PoE"
        vlan10_ip = "192.168.10.1"
        IP_CAM_ip = "192.168.10.99"
        #mainlogger.info("[%s]Starting- Ping IP CAM"%(checkitem))
        #device.device_send_command("config app-engine 0 disable")
        #time.sleep(30)
        checkcommandlist = ["show poe budget"]
        checkitemlist = ["Oper. Limit: 61.6 watts"]
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(mainlogger,device,checkitem,value,checkmatch)
            time.sleep(5)
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def Checking_Dialer_1020(device):
    try:
        dialer0_index = 0
        dialer1_index = 1
        cellular_index = 0
        #dialer_carrier = "TWM"
        WAN_ip = "8.8.8.8"
        cellular0_usb_index="usb1"
        cellular1_usb_index = "usb2"

        checkitem ="Checking_Dialer_1020"
        #device.device_send_command("Show PoE budget")

        mainlogger.info("[%s]Starting- show interface all"%(checkitem))
        #device.device_send_command("config app-engine 0 disable")
        #time.sleep(30)
        checkcommandlist = ["show interface all","ping -I %s -c5 %s"%(cellular0_usb_index,WAN_ip ),"ping -I %s -c5 %s"%(cellular1_usb_index,WAN_ip )]
        checkitemlist = ["dialer %s (.*) up | dialer %s (.*) up"%(dialer0_index,dialer1_index),"64 bytes from %s: icmp_seq=5 (.*)"%(WAN_ip),"64 bytes from %s: icmp_seq=5 (.*)"%(WAN_ip)]

        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(mainlogger,device,checkitem,value,checkmatch)
            time.sleep(5)
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def Checking_Dialer_1010(device):
    try:
        dialer0_index = 0
        dialer1_index = 1
        cellular_index = 0
        #dialer_carrier = "TWM"
        WAN_ip = "8.8.8.8"
        cellular0_usb_index="usb1"

        checkitem ="Checking_Dialer_1010"
        #device.device_send_command("Show PoE budget")

        mainlogger.info("[%s]Starting- show interface all"%(checkitem))
        #device.device_send_command("config app-engine 0 disable")
        #time.sleep(30)
        checkcommandlist = ["show interface all","ping -I %s -c5 %s"%(cellular0_usb_index,WAN_ip )]
        checkitemlist = ["dialer %s (.*) up"%(dialer0_index),"64 bytes from %s: icmp_seq=5 (.*)"%(WAN_ip)]

        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(mainlogger,device,checkitem,value,checkmatch)
            time.sleep(5)
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def Checking_Vlan(device):
    try:
        vlan1_index = 1000
        vlan50_index = 500
        checkitem ="Checking_Vlan"
        Vlan1_ip="172.99.1.63"
        Vlan50_ip = "172.116.1.63"

        mainlogger.info("[%s]Starting- Ping Interface"%(checkitem))
        #device.device_send_command("config app-engine 0 disable")
        #time.sleep(30)
        checkcommandlist = ["show interface all","ping -S %s -c5 192.168.100.1"%(Vlan1_ip),"ping -S %s -c5 192.168.100.1"%(Vlan50_ip)]
        checkitemlist = ["vlan %s (.*) up | vlan %s (.*) up"%(vlan1_index,vlan50_index) ,"64 bytes from 192.168.100.1: icmp_seq=5 (.*)","64 bytes from 192.168.100.1: icmp_seq=5 (.*)"]
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(mainlogger,device,checkitem,value,checkmatch)
            time.sleep(5)

    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def Checking_WDU_Vlan(device):
    try:
        vlan2_index = 2
        vlan5_index = 5

        WDU_vlan20_ip = "182.16.1.63"
        WDU_vlan50_ip = "182.116.3.63"
        vlan20_gw="182.16.1.254"
        vlan50_gw="182.116.15.254"

        checkitem ="Checking_WDU_Vlan"
        #device.device_send_command("Show PoE budget")

        mainlogger.info("[%s] Starting- Checking WDU"%(checkitem))

        checkcommandlist = ["ifconfig br0.%s"%(vlan2_index),"ifconfig br0.%s"%(vlan5_index),"show mobility tunnel all","show mobility tunnel all","ping -S %s -c5 %s"%(WDU_vlan20_ip,vlan20_gw),"ping -S %s -c5 %s"%(WDU_vlan50_ip,vlan50_gw),"ping -S %s -c5 %s"%(WDU_vlan20_ip, WDU_vlan50_ip)]
        checkitemlist = ["br0.2 | flags=4163<UP,BROADCAST,RUNNING |inet %s | "%(WDU_vlan20_ip),"br0.5 | flags=4163<UP,BROADCAST,RUNNING | inet %s"%(WDU_vlan50_ip),"dialer 0 | UA","dialer 1 | UA","64 bytes from %s: icmp_seq=5 (.*)"%(vlan20_gw),"64 bytes from %s: icmp_seq=5 (.*)"%(vlan50_gw),"64 bytes from %s: icmp_seq=5 (.*)"%( WDU_vlan50_ip)]
        for index,value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(mainlogger,device,checkitem,value,checkmatch)
            time.sleep(5)
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

def Checking_Tunnel(device):
    try:
        checkitem = "Checking_Tunnel"
        interfacelist = ['dialer 0', 'maintenance 0']
        devicelist = ['usb1', 'eth0']
        tunnel_control_server = "60.248.28.102"
        mainlogger.info("[%s] Starting- Checking Tunnel" % (checkitem))
        times = 2
        for k in range(0, times):
            for index, value in enumerate(interfacelist):
                    commanditem = "show mobility tunnel all"
                    commandstatus = "%s (.*) UA" % (value)
                    checkresult = device.device_send_command_match(commanditem, 7, commandstatus)
                    mainlogger.info("[%s]%s check %s result :%s" % (k, commandstatus, commanditem, checkresult))
                    if checkresult == False:
                        mainlogger.info("[%s]%s check %s error :%s" % (k, commandstatus, commanditem, device.target_response))
                        commanditem = "ping -I %s -c5 %s" % (devicelist[index], tunnel_control_server)
                        commandstatus = "64 bytes from %s: icmp_seq=5 (.*)" % (tunnel_control_server)
                        checkresult = device.device_send_command_match(commanditem, 7, commandstatus)
                        mainlogger.info("[%s]%s check %s result :%s" % (k, commandstatus, commanditem, checkresult))
                        if checkresult == False:
                            mainlogger.info("[%s]%s check %s error :%s" % (k, commandstatus, commanditem, device.target_response))
                            commanditem = "show interface all"
                            commandstatus = "%s (.*) up" % (value)
                            checkresult = device.device_send_command_match(commanditem, 7, commandstatus)
                            mainlogger.info("[%s]%s check %s result :%s" % (k, commandstatus, commanditem, checkresult))
                            if checkresult == False:
                                mainlogger.info("[%s]%s check %s error :%s" % (k, commandstatus, commanditem, device.target_response))
    except Exception, ex:
        logging.error("[NPI]exception fail:%s " % (str(ex)))

if __name__ == '__main__':
    if len(sys.argv) > 4:
        device_info = sys.argv[1].split("_")
        login_info = sys.argv[2].split("_")
        din_relay_info = sys.argv[3].split("_")
        powercycle_info = sys.argv[4].split("_")
        device_connect_type = device_info[0]
        device_ip = device_info[1]
        device_port = int(device_info[2])
        username = login_info[0]
        password = login_info[1]
        din_relay_ip = din_relay_info[0]
        din_relay_user = din_relay_info[1]
        din_relay_pwd = din_relay_info[2]
        din_relay_device_name = din_relay_info[3]
        test_cycle = int(powercycle_info[0])
        power_cycle_sleep = int(powercycle_info[1])
        print sys.argv
    else:
        logfilename = "NPI%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
        #mainlogger = set_log(logfilename,"NPI")
        device_ip = "10.2.53.158"
        device_port = 22
        device_connect_type ="ssh"
        username = "admin"
        password ="admin"
        din_relay_ip = "10.2.53.199"
        din_relay_user ="root"
        din_relay_pwd ="lilee1234"
        din_relay_device_name = "R1-158"
            #"R1-Alpha-STS2"
        test_cycle = 1000
        power_cycle_sleep = 180
        Sata0_size = "29.8G"

        try:
            device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"NPI")
            powerCycle = powerCycle()
            if device:
                device.device_get_version()
                model_name = device.device_product_name.split("-")[1].lower()
                mainlogger.info("Device Bios Version:%s"%(device.bios_version))
                mainlogger.info("Device recovery image:%s"%(device.boot_image))
                mainlogger.info("Device build image:%s"%(device.build_image))
                for k in range(0, test_cycle):
                    power_cycle_result = powerCycle.powerControl(din_relay_ip, din_relay_user, din_relay_pwd, din_relay_device_name )
                    mainlogger.info("[%s][power_cycle_result]result :%s"%(k,power_cycle_result))
                    if power_cycle_result:
                        mainlogger.info("[%s][power_cycle_sleep]%s seconds"%(k,power_cycle_sleep))
                        time.sleep(180)
                        count = check_booting(device_ip,power_cycle_sleep)
                        mainlogger.info("[%s][power_cycle_sleep]wait %s seconds"%(k,count))
                        if count < power_cycle_sleep:
                            #time.sleep(power_cycle_sleep)
                            device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"NPI")
                            if device:
                                checkitem = "device_check_interface_and_mobility"
                                mainlogger.info("[%s]Starting" % (checkitem))
                                device.device_send_command("update terminal paging disable")
                                Sata0_result = device.device_send_command("/usr/sbin/udevadm info -q name --name=/dev/disk/by-path/pci-0000:00:13.0-ata-1.0")
                                if Sata0_result:
                                    sub_match = re.findall('sd(.*)\n', device.target_response)
                                    if sub_match:
                                        Sata0 = "sd%s" % (sub_match[0])
                                checkitem = "device_check_interface_and_mobility"
                                mainlogger.info("[%s]Starting" % (checkitem))
                                if model_name != "1010":
                                    Sata0_size = "953.9G"
                                checkcommandlist = ["show interface all", "lsblk -l | grep %s | grep disk" % (Sata0)]
                                checkitemlist = ["maintenance 0 (.*) up", "%s" % (Sata0_size)]
                                for index, value in enumerate(checkcommandlist):
                                    checkmatch = checkitemlist[index]
                                    device_check_info(mainlogger, device, checkitem, value, checkmatch)

                                Checking_PoE(device)
                                if model_name != "1010":
                                    print model_name
                                    Checking_Dialer_1020(device)
                                    Checking_Wifi_1020(device)
                                else:
                                    print model_name
                                    Checking_Dialer_1010(device)
                                    Checking_Wifi_1010(device)
                                Checking_Tunnel(device)
                                Checking_Vlan(device)
                                Checking_WDU_Vlan(device)
                                Checking_GPS(device)

        except Exception,ex:
            logging.error("[NPI]exception fail:%s "%(str(ex)))


