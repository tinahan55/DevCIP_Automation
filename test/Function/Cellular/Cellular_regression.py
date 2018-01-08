__author__ = 'Lance'
from lib.Device import *
from lib.Configuration import *
import os
from lib.SSHConsole import *

logger = Log("Cellular_pretest","Cellular_pretest")
networktool = Network()
Server_Type = ""
def set_log(filename, loggername):
    logpath = os.path.join(os.getcwd(), 'log')
    if not os.path.exists(logpath):
        os.makedirs(logpath)
    filepath = os.path.join(logpath, filename)
    logger = logging.getLogger(loggername)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s -%(message)s')
    fh = logging.FileHandler(filepath)
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger

def device_check_info(logger, device, checkitem, checkcommand, checkmatch):
    title = "[%s][%s]" % (checkitem, checkcommand)
    logger.info("%s starting" % (title))
    checkresult = device.device_send_command_match(checkcommand, 10, checkmatch)
    logger.info("%s check %s result: %s" % (title, checkmatch, checkresult))
    if checkresult == False:
        logger.error("%s check %s error: %s" % (title, checkmatch, device.target_response))
        current_config = device.device_send_command("show running-configuration")
        logger.error("current config: %s" % current_config)

    return checkresult

def  check_booting(hostip,check_cycle):
    k = 0
    while k < check_cycle:
        if networktool.Host_Ping(hostip,10):
            break
        else:
            time.sleep(1)
        k+=1
    return True

def get_cellular_port(): # For cellular index
    #port_array = "2/2"
    if  "LMS" in Server_Type:
        index= "0/1"
    elif "DTS" in Server_Type:
        index="0/1"
    elif "STS" in Server_Type:
         index="0"
    return index

def Cellular_Iccid_info(device):
    logger.info("[Cellular_Iccid-info] Testing start...")
    server_command = "show interface cellular %s detail"%(cellular_index) #"show sim-management current-status" #show interface cellular 0 detail
    server_command_match = "ICCID : %s" % (Iccid00)
    result0 = device.device_send_command_match(server_command, 20, server_command_match)
    # matchresult = server_device.device_send_command_match(server_command, 20, server_command_match)
    if result0 == False:
        logger.info("[Cellular_Iccid-info] test  fail!!")
    else:
        logger.info("[Cellular_Iccid-info] Successfully!!!")
    logger.info("[Cellular_Iccid-info] is %s..."% (result0))
    return result0

def Cellular_RRC_Check(device):
    device.device_send_command("ping -c 5 -I cellular%s 8.8.8.8"%(int(cellular_index)))
    RRC_command = "show interface cellular %s detail" % (cellular_index)
    RRC_command_match= "RRC State : RRC Connected"
    logger.info("[Cellular_RRC_Check] Testing start...")
    matchresult = device.device_send_command_match(RRC_command , 10,RRC_command_match)
    if (matchresult == False):
        logger.info("[Cellular_RRC_Check] test  fail!!")
    else:
        logger.info("[Cellular_RRC_Check] Successfully!!!")
    logger.info("[DUT] Check Cellular RRC state is %s"%(matchresult))
    return matchresult

def Set_cellular(device):
    configlist = list()
    # profile and dialer
    profile_name = "Auto"
    access_name = "internet"
    apn_name1="internet"
    apn_name2="wrong"
    simslot_index=0
    result = False
    logger.info("[DUT] Enable interface cellular")
    profile = Profile("Profile")
    configlist.extend(profile.get_sim_profile(profile_name, apn_name1))
    interface_dialer = Interface("server_dialer")
    configlist.extend(interface_dialer.get_cellular_interface(profile_name, cellular_index,simslot_index))

    device.device_set_configs(configlist)

    time.sleep(10)
    checkitem = "Set_cellular"
    checkcommandlist = [ "show interface cellular %s detail" % (cellular_index),"show interface all"]
    checkitemlist = ["Radio Access Technology : LTE","cellular %s(.*)up"%(cellular_index)]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result =device_check_info(logger, device, checkitem, value, checkmatch)
        time.sleep(10)
        if result == False:
            #print device.target_response
            return result
    logger.info("[DUT] Enable interface dialer is %s"%(result))
    return result

if __name__ == '__main__':
    connecttype = "telnet"
    set_result = True
    test_cycle = 10
    server_ip = "10.2.66.50" # STS ip 10.2.66.65, LMS ip 10.2.66.64
    server_port = 2040
    server_maintenance_ip = "10.2.66.65"
    server_login_user ="admin"
    server_login_password ="admin"
    if len(sys.argv) >1:
        #connect_type = sys.argv[1]
        Server_Info = sys.argv[1] #telnet_10.2.66.50_2040_10.2.66.65_admin_admin
        server_connect_type = Server_Info.split("_")[0]
        server_ip =Server_Info.split("_")[1]
        server_port =Server_Info.split("_")[2]
        server_maintenance_ip = Server_Info.split("_")[3]
        server_login_user = Server_Info.split("_")[4]
        server_login_password = Server_Info.split("_")[5]

    #DUT set configuration
    logger.info("Cellular_pretest")
    # Check the device is available or not by 'check_booting'
    if check_booting(server_maintenance_ip, test_cycle) == False:  #Make sure device is alive before ececute testing
        sys.exit(0)

    server_device = Device_Tool(server_ip, server_port, connecttype, server_login_user, server_login_password,
                                "Cellular_pretest")
    if server_device.target:
        server_device.device_send_command("update terminal paging disable", 5)
        server_device.device_get_version()
        server_device.device_get_hostname()
        server_device.device_get_register_MAC("maintenance 0")
        logger.write("info", "Server Device type:%s" % (server_device.device_type))
        logger.write("info", "Server Device Bios Version:%s" % (server_device.bios_version))
        logger.write("info", "Server Device recovery image:%s" % (server_device.boot_image))
        logger.write("info", "Server Device build image:%s" % (server_device.build_image))
        logger.write("info", "Server Device testrail image:%s" % (server_device.testrail_build_version))
        logger.write("info", "Server Device mac:%s" % (server_device.device_register_MAC))
        logger.write("info", "Server Device hostname:%s" % (server_device.device_hostname))
        logger.write("info", "Server Device version:%s" % (server_device.branch_version))

        Server_Type = server_device.device_product_name
        server_device.device_send_command("config switch port 0 disable")
        #sys.exit(0)

    if server_device:
        #dialer_index = get_dialer_port()
        cellular_index = get_cellular_port()
        print Server_Type

        if "STS" in Server_Type:
            Iccid00 = "89886920041308836573"
            Iccid01 = "89886891000087039135"
        else:
            Iccid00 = "89886891000087039127"
            Iccid01 = "89886920031026180016"

        set_result = Cellular_Iccid_info(server_device)
        if set_result: set_result = Set_cellular(server_device)
        if set_result: set_result =Cellular_RRC_Check(server_device) # Dialer should be on 4G mode, 3G not support RRC state.
        logger.info("[DUT]Server show the configuration ...")
        logger.info("[DUT] %s" % (server_device.device_get_running_config()))
        #if set_result: set_result = Dialer_Simlot_Change(server_device)

        logger.info("[DUT]Celluar Basic Test Finished, result is %s" % (set_result))
        '''if set_result:
            if "STS" in Server_Type:
                set_result = Dialer_firmware_switch(server_device)'''

    logger.info("[DUT]Celluar Test Finished as %s" % (set_result))
    server_device.device_send_command("reboot")

    sqamail = sqa_mail()
    sqamail.send_mail("lance.chien@lileesystems.com", "Celluar Test %s"%(set_result), u"%s" %(set_result))
