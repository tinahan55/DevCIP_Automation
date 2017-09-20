__author__ = 'Jess'

from lib.Device import *
from lib.Configuration import *
from lib.Tool import *
import logging
import os
from time import gmtime, strftime

AP_Server_Type = ""
STA_Server_Type = ""

logger = Log("wifi_regression", "wifi_pretest")

def device_check_info(logger, device, checkitem, checkcommand, checkmatch):
    title = "[%s][%s]" % (checkitem, checkcommand)
    logger.info("%s starting" % (title))
    checkresult = device.device_send_command_match(checkcommand, 5, checkmatch)
    logger.info("%s check %s result :%s" % (title, checkmatch, checkresult))
    if checkresult == False:
        logger.info("%s check %s error :%s" % (title, checkmatch, device.target_response))

def get_wifi_wlan0_index():
    if "lms" in AP_Server_Type:
        wlan0_index = "1/1"
    elif "dts" in AP_Server_Type:
        wlan0_index = "0/1"
    elif "sts" in AP_Server_Type:
        wlan0_index = "0"
    return wlan0_index

def get_wifi_wlan1_index():
    if "lms" in STA_Server_Type:
        wlan1_index = "1/2"
    elif "dts" in STA_Server_Type:
        wlan1_index = "0/2"
    elif "sts" in STA_Server_Type:
        wlan1_index = "1"
    return wlan1_index

def get_dhcp_interface():
    if "LMS" or "lms" in AP_Server_Type:
        dhcp_interface = "wlan 0/1"
    elif "DTS" or "dts" in AP_Server_Type:
        dhcp_interface = "wlan 0/1"
    elif "STS" or "sts" in AP_Server_Type:
        dhcp_interface = "wlan 0"
    return dhcp_interface

def set_ap(device, operating_mode, security, wpa_version):
#parameters
    configlist = list()
    wpa_key = "ilovelilee"
    ssid_name = security
    profile_name = security
    wlan0_mode = "ap"
    wlan0_ip_mode = "static"
    wlan0_ip_address = "172.10.88.12"
    wlan0_ip_netmask = "255.255.255.0"
#config wifi ap profile
    profile = WifiProfile("wifi_ap_profile")
    if security == "open":
        configlist.extend(profile.get_wificonfig_open(wlan0_mode, profile_name, ssid_name))
    elif security == "wpa":
        configlist.extend(profile.get_wificonfig_wpa_psk(wlan0_mode, profile_name, ssid_name, wpa_version, wpa_key))
    else:
        eap_type = security
        configlist.extend(profile.get_wificonfig_eap(wlan0_mode, profile_name, ssid_name, wpa_version, eap_type))

#config wifi ap interface
    interface = Interface("wifi_ap_interface")
    configlist.extend(interface.get_wifi_interface(wlan0_index, profile_name, wlan0_mode, wlan0_ip_mode, operating_mode, wlan0_ip_address, wlan0_ip_netmask))

    device.device_set_configs(configlist)
    time.sleep(90)
    logger.info("AP %s mode with %s security done!" %(operating_mode, security))
#check ap profile and interface
    checkitem = "Check_Wifi_AP_Profile_Interface"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["show interface all", "show wifi-profile %s" %(security)]
    checkitemlist = ["wlan %s&&up" % (wlan0_index), "Profile Name : open&&SSID : open"]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger, device, checkitem, value, checkmatch)
        time.sleep(10)
        if result == False:
            return result
    return result

def set_sta(device, operating_mode, security, wpa_version):
#parameters
    configlist = list()
    wlan1_ip_address = "172.10.88.13"
    wlan1_ip_netmask = "255.255.255.0"
    ssid_name = security
    profile_name = security
    wlan1_mode = "sta"
    wlan1_ip_mode = "static"
    wpa_key = "ilovelilee"
    ca_cert_link = "http://10.2.10.189/Tmp_Files/ca.pem"
    client_cert_link = "http://10.2.10.189/Tmp_Files/client.p12"
    client_link = "http://10.2.10.189/Tmp_Files/client.pem"
    test_ap_ip = "172.10.88.12"
#config wifi sta profile
    profile = WifiProfile("wifi_sta_profile")
    if security == "open":
        configlist.extend(profile.get_wificonfig_open(wlan1_mode, profile_name, ssid_name))
    elif security == "wpa":
        configlist.extend(profile.get_wificonfig_wpa_psk(wlan1_mode, profile_name, ssid_name, wpa_version, wpa_key))
    else:
        eap_type = security
        checkresult = device.device_send_command_match("show certificate", 5, "ca.pem")
        if checkresult == False:
            device.device_send_command("update certificate %s" % (ca_cert_link))
            time.sleep(10)
            device.device_send_command("update certificate %s" % (client_cert_link))
            time.sleep(10)
            device.device_send_command("update certificate %s" % (client_link))
            time.sleep(10)
        else:
            print "no need to upgrade certificate files!"
        configlist.extend(profile.get_wificonfig_eap(wlan1_mode, profile_name, ssid_name, wpa_version, eap_type))

#config sta interface
    interface = Interface("wifi_sta_interface")
    configlist.extend(interface.get_wifi_interface(wlan1_index, profile_name, wlan1_mode, wlan1_ip_mode, operating_mode, wlan1_ip_address, wlan1_ip_netmask))

    device.device_set_configs(configlist)
    time.sleep(90)
    logger.info("STA %s mode with %s security done!" %(operating_mode, security))
#check connection between AP and STA
    checkitem = "Check_Wifi_STA_Profile_Interface_Connection"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["show wifi-profile %s" % (profile_name), "show interface all", "ping -I 172.10.88.13 -c 5 %s" %(test_ap_ip)]
    checkitemlist = ["Profile Name : %s && SSID : %s" % (profile_name, ssid_name), "wlan %s && up" % (wlan1_index),"64 bytes from %s: icmp_seq=5 (.*)" % (test_ap_ip)]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger, device, checkitem, value, checkmatch)
        time.sleep(10)
        if result == False:
            return result
    return result

def set_log(filename, loggername):
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
    connecttype = "telnet"
    #server_ap_ip = "10.2.66.50"     #R11-LMS-1
    server_ap_ip = "10.2.11.7"
    server_sta_ip = "10.2.11.4"    #R11-DTS-1
    server_ap_port = 4006
    server_sta_port = 3009
    server_ap_maintenance_ip = "10.2.11.154"
    server_sta_maintenance_ip = "10.2.9.123"
    server_ap_login_user = "admin"
    server_ap_login_password = "admin"
    server_sta_login_user = "admin"
    server_sta_login_password = "admin"

    if len(sys.argv) > 2:
        connect_type = sys.argv[1]
        AP_Info = sys.argv[2] #telnet_10.2.66.50_2040_10.2.66.61_admin_admin =>connecttype_ip_port_maintenceip_username_password
        ap_connect_type = AP_Info.split("_")[0]
        ap_ip = AP_Info.split("_")[1]
        ap_port = AP_Info.split("_")[2]
        ap_maintenance_ip = AP_Info.split("_")[3]
        ap_login_user = AP_Info.split("_")[4]
        ap_login_password = AP_Info.split("_")[5]

        STA_Info = sys.argv[3]#telnet_10.2.66.50_2035_admin_admin =>connecttype_ip_port_maintenceip_username_password
        sta_connect_type = STA_Info.split("_")[0]
        sta_client_ip = STA_Info.split("_")[1]
        sta_client_port = STA_Info.split("_")[2]
        sta_maintenance_ip = STA_Info.split("_")[3]
        sta_login_user = STA_Info.split("_")[4]
        sta_login_password = STA_Info.split("_")[5]

    ap_device = Device_Tool(server_ap_ip, server_ap_port, connecttype, server_ap_login_user, server_ap_login_password, "wifi_pretest")
    sta_device = Device_Tool(server_sta_ip, server_sta_port, connecttype, server_sta_login_user, server_sta_login_password, "wifi_pretest")

    if ap_device.target:
        ap_device.device_send_command("update terminal paging disable", 5)
        ap_device.device_get_version()
        ap_device.device_get_hostname()
        ap_device.device_get_register_MAC("maintenance 0")
        logger.write("info", "Server Device type:%s" % (ap_device.device_type))
        logger.write("info", "Server Device Bios Version:%s" % (ap_device.bios_version))
        logger.write("info", "Server Device recovery image:%s" % (ap_device.boot_image))
        logger.write("info", "Server Device build image:%s" % (ap_device.build_image))
        logger.write("info", "Server Device testrail image:%s" % (ap_device.testrail_build_version))
        logger.write("info", "Server Device mac:%s" % (ap_device.device_register_MAC))
        logger.write("info", "Server Device hostname:%s" % (ap_device.device_hostname))
        logger.write("info", "Server Device version:%s" % (ap_device.branch_version))
        AP_Server_Type = ap_device.device_type

    if sta_device.target:
        sta_device.device_send_command("update terminal paging disable", 5)
        sta_device.device_get_version()
        sta_device.device_get_hostname()
        sta_device.device_get_register_MAC("maintenance 0")
        logger.write("info", "Server Device type:%s" % (sta_device.device_type))
        logger.write("info", "Server Device Bios Version:%s" % (sta_device.bios_version))
        logger.write("info", "Server Device recovery image:%s" % (sta_device.boot_image))
        logger.write("info", "Server Device build image:%s" % (sta_device.build_image))
        logger.write("info", "Server Device testrail image:%s" % (sta_device.testrail_build_version))
        logger.write("info", "Server Device mac:%s" % (sta_device.device_register_MAC))
        logger.write("info", "Server Device hostname:%s" % (sta_device.device_hostname))
        logger.write("info", "Server Device version:%s" % (sta_device.branch_version))
        STA_Server_Type = sta_device.device_type

    wlan0_index = get_wifi_wlan0_index()
    wlan1_index = get_wifi_wlan1_index()

#open security
    set_ap(ap_device, "2.4g", "open", "1")
    set_sta(sta_device, "2.4g", "open", "1")
    set_ap(ap_device, "5g", "open", "1")
    set_sta(sta_device, "5g", "open", "1")
    set_ap(ap_device, "ac", "open", "1")
    set_sta(sta_device, "ac", "open", "1")
#wpa-psk security
    set_ap(ap_device, "2.4g", "wpa", "1")
    set_sta(sta_device, "2.4g", "wpa", "1")
    set_ap(ap_device, "5g", "wpa", "auto")
    set_sta(sta_device, "5g", "wpa", "auto")
    set_ap(ap_device, "ac", "wpa", "2")
    set_sta(sta_device, "ac", "wpa", "2")
#wpa-eap peap security
    set_ap(ap_device, "2.4g", "peap", "auto")
    set_sta(sta_device, "2.4g", "peap", "auto")
    set_ap(ap_device, "5g", "peap", "1")
    set_sta(sta_device, "5g", "peap", "1")
    set_ap(ap_device, "ac", "peap", "2")
    set_sta(sta_device, "ac", "peap", "2")
#wpa-eap tls security
    set_ap(ap_device, "2.4g", "tls", "1")
    set_sta(sta_device, "2.4g", "tls", "1")
    set_ap(ap_device, "5g", "tls", "auto")
    set_sta(sta_device, "5g", "tls", "auto")
    set_ap(ap_device, "ac", "tls", "2")
    set_sta(sta_device, "ac", "tls", "2")

    logger.info("WiFi Test Finished")
    #ap_device.device_send_command("reboot")
    #sta_device.device_send_command("reboot")
            # server_device.device_send_command("reboot")
            # logger.info("[DUT]Celluar Test Finished as %s" %(set_result))
            # sqamail = sqa_mail()
            # sqamail.send_mail("lance.chien@lileesystems.com", "Celluar Test %s"%(set_result), u"%s" %(set_result))
