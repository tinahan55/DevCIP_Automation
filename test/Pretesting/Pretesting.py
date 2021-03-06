from lib.Device import *
from lib.Configuration import *
from lib.TestRail import *
import logging
import os
from time import gmtime, strftime


def get_dialer_port(): # For interface dialer
    #port_array = "2/2"
    port=""
    if  "LMS" in Server_Type:
        port= "0"
    elif "DTS" in Server_Type:
        port="0"
    elif "STS" in Server_Type:
         port="0"
    return port

def get_cellular_port(): # For cellular index
    #port_array = "2/2"
    index=""
    if  "LMS" in Server_Type:
        index= "0/1"
    elif "DTS" in Server_Type:
        index="0/1"
    elif "STS" in Server_Type:
         index="0"
    return index

def get_wifi_wlan0_index():
    wlan0_index = ""
    if "LMS" in Server_Type:
        wlan0_index = "1/1"
    elif "DTS" in Server_Type:
        wlan0_index = "0/1"
    elif "STS" in Server_Type:
        wlan0_index = "0"
    return wlan0_index

def get_wifi_wlan1_index():
    wlan1_index = ""
    if "LMS" in Server_Type:
        wlan1_index = "1/2"
    elif "DTS" in Server_Type:
        wlan1_index = "0/2"
    elif "STS" in Server_Type:
        wlan1_index = "1"
    return wlan1_index

def device_check_info(logger,device,checkitem,checkcommand,checkmatch):
    title = "[%s][%s]"%(checkitem,checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand,5,checkmatch)
    logger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
    if checkresult== False:
        print device.target_response
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))
    return checkresult

def Pretesting_Cellular(device):
    configlist = list()
    # profile and dialer
    profile_name = "Auto"
    access_name = "internet"
    apn_name1 = "internet"
    apn_name2 = "wrong"
    simslot_index = 0
    result = False
    logger.info("[DUT] Enable interface cellular")
    profile = Profile("Profile")
    configlist.extend(profile.get_sim_profile(profile_name, apn_name1))
    interface_dialer = Interface("server_dialer")
    configlist.extend(interface_dialer.get_cellular_interface(profile_name, cellular_index, simslot_index))

    device.device_set_configs(configlist)

    time.sleep(10)
    checkitem = "Set_cellular"
    checkcommandlist = ["show interface cellular %s detail" % (cellular_index), "show interface all"]
    checkitemlist = ["Radio Access Technology : LTE", "cellular %s(.*)up" % (cellular_index)]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        cellular_result = device_check_info(logger, device, checkitem, value, checkmatch)
        time.sleep(10)
        if cellular_result == False:
            # print device.target_response
            logger.info("[Pretesting_Cellular] Test  fail!!")
            return "FAIL"
        else:
            logger.info("[Pretesting_Cellular] Successfully!!!")
            return "PASS"

def Dialer_Iccid_info(device):
    logger.info("[Cellular_Iccid-info] Testing start...")
    server_command = "show interface cellular %s detail" % (
        cellular_index)  # "show sim-management current-status" #show interface cellular 0 detail
    server_command_match = "ICCID : %s" % (Iccid00)
    result0 = device.device_send_command_match(server_command, 20, server_command_match)
    # matchresult = server_device.device_send_command_match(server_command, 20, server_command_match)
    if result0 == False:
        logger.info("[Cellular_Iccid-info] test  fail!!")
        return "FAIL"
    else:
        logger.info("[Cellular_Iccid-info] Successfully!!!")
        return "PASS"

def OS_1410(device):
    wlan0_mac_address = "04:f0:21:25:46:7b"
    wlan1_mac_address = "04:f0:21:25:46:7a"
    checkitem = "Check_OS-1410"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["ifconfig wlan0", "ifconfig wlan1"]
    checkitemlist = ["ether %s" %(wlan0_mac_address), "ether %s" %(wlan1_mac_address)]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger, device, checkitem, value, checkmatch)
    return result

def Pretesting_WiFi(device):
    #######################################################################
    # 1. WLAN0 and WLAN1 MAC might have chance to swap            (dine)  #
    # 2. Deploy WiFi to AP mode and use authentication WPA2       (done)  #
    # 3. Check WiFi protocol with 802.11ac 5GHz                   (done)  #
    # 4. Deploy WiFi to STA mode and use authentication WPA2-PSK  (done)  #
    #######################################################################
    #setting AP parameters
    wifi_ip_address = "172.20.0.1"
    wifi_ip_address_mask = "255.255.255.0"
    ap_ssid_name = "WifiPretest"
    ap_password = "12345678"
    #setting STA parameters
    sta_ssid_name = "SJ-STS-Alpha"
    sta_password = "ilovelilee"

    logger.info("[Pre-testing_WiFi] Testing start...")
    #setting AP
    device.device_send_command("config interface wlan %s ip address %s netmask %s" %(wlan0_index, wifi_ip_address, wifi_ip_address_mask))
    device.device_send_command("config interface wlan %s access-point ssid %s" %(wlan0_index, ap_ssid_name))
    device.device_send_command("config interface wlan %s access-point authentication key-management wpa-psk" %(wlan0_index))
    device.device_send_command("config interface wlan %s access-point authentication wpa-version 2" %(wlan0_index))
    device.device_send_command("config interface wlan %s access-point authentication wpa-psk-passphrase %s" %(wlan0_index, ap_password))
    device.device_send_command("config interface wlan %s mode access-point"%(wlan0_index))
    device.device_send_command("config interface wlan %s band 5-ghz" %(wlan0_index))
    device.device_send_command("config interface wlan %s enable" %(wlan0_index))
    time.sleep(60)
    #setting STA
    device.device_send_command("config interface wlan %s ip address dhcp" %(wlan1_index))
    device.device_send_command("config interface wlan %s station ssid %s" %(wlan1_index, sta_ssid_name))
    device.device_send_command("config interface wlan %s station authentication key-management wpa-psk" %(wlan1_index))
    device.device_send_command("config interface wlan %s station authentication wpa-psk-passphrase %s" %(wlan1_index,sta_password))
    device.device_send_command("config interface wlan %s mode station" %(wlan1_index))
    device.device_send_command("config interface wlan %s enable" %(wlan1_index))
    time.sleep(120)


    checkitem = "Pretesting_WiFi"
    checkcommandlist = ["show interface wlan %s detail" %(wlan0_index),"show interface wlan 0 interface-info",
                        "show interface wlan 1 detail", "ping -I wlan1 -c 5 172.20.5.1"]
    checkitemlist = ["Administrative : enable&&Operational : up", "SSID : %s" %(ap_ssid_name), "Administrative : enable&&Operational : up",
                     "64 bytes from 172.20.5.1: icmp_seq=5"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        wifi_result = device_check_info(logger,device,checkitem,value,checkmatch)
        if wifi_result == False:
            print device.target_response
            break

    if wifi_result:
        logger.info("[Pretesting_Wifi] Successfully!!!")
        return "PASS"
    else:
        logger.info("[Pretesting_WiFi] Test failed!!!")
        return "FAIL"

def Pretesting_Poe(device):

    checkitem ="Pretesting_Poe"
    checkcommandlist = ["show poe budget"]
    if device_type == "sts":
        checkitemlist = ["Oper. Limit: 61.6 watts"]
    else:
        checkitemlist = [" Oper.Limit: 132.6 watts"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result3 = device_check_info(logger,device,checkitem,value,checkmatch)
        if result3 == False:
            logger.info("[Pretesting_Poe] Test  fail!!")
            return "FAIL"
        else:
            logger.info("[Pretesting_Poe] Successfully!!!")
            return "PASS"
        logger.info("[Pretesting_Poe] is %s..."% (result3))

def Pretesting_GPS(device):

    checkitem ="Pretesting_GPS"
    checkcommandlist = ["config service gps disable","show gps detail","no config service gps disable","show gps detail"]

    checkitemlist = ["localdomain","GPS status : Disabled","localdomain","Fix Quality : 3D | Latitude : 25(.*) | Longitude : 121(.*)"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result4 = device_check_info(logger,device,checkitem,value,checkmatch)
        if result4 == False:
            print device.target_response
            break

    if result4:
        logger.info("[Pretesting_GPS] Successfully!!!")
        return "PASS"
    else:
        logger.info("[Pretesting_GPS] Test  fail!!")
        return "FAIL"

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

def Pretesting_CLI(device):

    checkitem = "Pretesting_CLI"
    checkcommandlist = ["show version","show platform led","show interface all"]

    checkitemlist = ["%s"%(device.build_image),"RDY            green","maintenance 0(.*)up"]

    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result5 = device_check_info(logger, device, checkitem, value, checkmatch)
        if result5 == False:
            print device.target_response
            break
    if result5 == False:
        logger.info("[Pretesting_CLI] test  fail!!")
        return "FAIL"
    else:
        logger.info("[Pretesting_CLI] Successfully!!!")
        return "PASS"
    logger.info("[Pretesting_CLI] is %s..." % (result5))

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
    logger = set_log(logfilename,"Pretesting")
    public_ping_ip = "8.8.8.8"

    project_name ="LileeOS"
    test_plan = "LileeOS_Weekly_Pretest"
    #test_run = "PreTesting"
    comment = "Auto result upload by SQA"
    testrail =TestRailAPI(logname="Pretesting")

    if len(sys.argv)>1:
        device_info =sys.argv[1].split("_") #ssh_10.2.66.52_22_admin_admin
        # device_info
        device_connect_type = device_info[0]
        device_ip = device_info[1]
        device_port = int(device_info[2])
        username = device_info[3]
        password = device_info[4]
    else:
        device_ip = "10.2.66.65"
        device_port = 22
        device_connect_type = "ssh"
        username = "admin"
        password = "admin"

    device = Device_Tool(device_ip, device_port, device_connect_type, username, password, "Pretesting")
    if device:
        device.device_send_command("update terminal paging disable")
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        testrail_buildversion=device.build_image
        Server_Type = device.device_product_name
        device_type = device.device_type
        dialer_index = get_dialer_port()
        cellular_index = get_cellular_port()
        wlan0_index = get_wifi_wlan0_index()
        wlan1_index = get_wifi_wlan1_index()
        #print Server_Type
        if "STS" in Server_Type:
            Iccid00 = "89886920041308836573"
            Iccid01 = "89886891000087039135"
            #device_type = "STS"
        elif "LMS" in Server_Type:
            Iccid00 = "89886891000087039127"
            Iccid01 = "89886920031026180016"
            #device_type = "LMS"


        basic_dialer = Pretesting_Cellular(device)

        updateresult = testrail.update_test_result(project_name, test_plan, "Cellular", device_type, 7828,
                                                   testrail_buildversion, basic_dialer, comment, True)
        logger.info("[Update_Pretesting_Dialer_Basic]update_test_result : %s" % (updateresult))

        iccid_result = Dialer_Iccid_info(device)
        updateresult = testrail.update_test_result(project_name, test_plan, "Cellular", device_type, 6695,
                                                   testrail_buildversion, iccid_result, comment, True)
        logger.info("[Update_Pretesting_Dialer_ICCID]update_test_result : %s" % (updateresult))

        '''info_result = Dialer_Info(device)
        updateresult = testrail.update_test_result(project_name, test_plan, "Cellular", device_type, 15719,
                                                   testrail_buildversion, info_result, comment, True)
        logger.info("[Update_Pretesting_Dialer_Info]update_test_result : %s" % (updateresult))'''

        poe_result = Pretesting_Poe(device)
        updateresult = testrail.update_test_result(project_name, test_plan, "PoE", device_type, 6965,
                                                   testrail_buildversion, poe_result, comment, True)
        logger.info("[Update_Pretesting_PoE] is %s..." % (updateresult))

        gps_result = Pretesting_GPS(device)
        updateresult = testrail.update_test_result(project_name, test_plan, "GPS", device_type, 6899,
                                                   testrail_buildversion, gps_result, comment, True)
        updateresult = testrail.update_test_result(project_name, test_plan, "GPS", device_type, 7546,
                                                   testrail_buildversion, gps_result, comment, True)
        logger.info("[Update_Pretesting_GPS] is %s..." % (updateresult))

        #Pretesting_Appengine(device)

        cli_result = Pretesting_CLI(device)
        updateresult = testrail.update_test_result(project_name, test_plan, "CLI", device_type, 12008,
                                                   testrail_buildversion, cli_result, comment, True)
        updateresult = testrail.update_test_result(project_name, test_plan, "CLI", device_type, 12013,
                                                   testrail_buildversion, cli_result, comment, True)
        updateresult = testrail.update_test_result(project_name, test_plan, "CLI", device_type, 12016,
                                                   testrail_buildversion, cli_result, comment, True)
        logger.info("[Update_Pretesting_CLI] is %s..." % (updateresult))

        '''if device.device_type == "sts":
            wifi_result = Pretesting_WiFi(device)
            updateresult = testrail.update_test_result(project_name, test_plan, "WiFi", device_type, 6889,
                                                       testrail_buildversion, wifi_result, comment, True)
            updateresult = testrail.update_test_result(project_name, test_plan, "WiFi", device_type, 7330,
                                                       testrail_buildversion, wifi_result, comment, True)
            updateresult = testrail.update_test_result(project_name, test_plan, "WiFi", device_type, 9227,
                                                       testrail_buildversion, wifi_result, comment, True)
            logger.info("[Update_Pretesting_WiFi] is %s..." % (updateresult))'''
        #sqamail = sqa_mail()
        #sqamail.send_mail("lance.chien@lileesystems.com", "Celluar Test %s" % (set_result), u"%s" % (set_result))
        
