__author__ = 'lance.chien'


from lib.Configuration import *
from lib.Device import *
import os
from lib.TelnetConsole import *

Server_Type = "LMC"
logger = Log("Tunnel_test","Tunnel_test")


def device_check_info(logger, device, checkitem, checkcommand, checkmatch):
    title = "[%s][%s]" % (checkitem, checkcommand)
    logger.info("%s starting" % (title))
    checkresult = device.device_send_command_match(checkcommand, 5, checkmatch)
    logger.info("%s check %s result: %s" % (title, checkmatch, checkresult))
    if checkresult == False:
        logger.error("%s check %s error: %s" % (title, checkmatch, device.target_response))
        current_config = device.device_send_command("show running-configuration")
        logger.error("current config: %s" % current_config)

    return checkresult

def get_server_port_list():
    port_array = ["2/1", "2/2"]
    if  "LMS" in Server_Type:
        port_array = ["2/1", "2/2"]
    elif "DTS" in Server_Type:
        port_array=[1, 2]
    elif "STS" in Server_Type:
         port_array=[3, 2]
    return port_array

def get_client_port_index(vlan_index):
    port_index = "1"
    if "LMS" in Server_Type:
        if vlan_index == 10:
            port_index = "1"
        elif vlan_index == 20:
            port_index = "2"
    elif "DTS" in Server_Type:
        if vlan_index== 10 :
            port_index = "2/1"
        elif vlan_index == 20:
            port_index = "3"
    elif "STS" in Server_Type:
        if vlan_index== 10 :
            port_index = "2"
        elif vlan_index == 20:
            port_index = "2/2"
    return port_index

def Public_client_config(device):
    configlist = list()
    #set vlan
    vlan_index = 10
    vlan_description = "client1_vlan10"
    ip_mode = "static"
    ipaddress = "192.168.10.1"
    netmask = "255.255.255.0"
    # set port
    port_index = get_client_port_index(vlan_index)
    port_type = "port"
    vlan_tagged = "untagged"
    port_tagged = "untagged"
    #set route
    route_type = "ip"
    route_mode = "default"
    gateway = "192.168.10.254"

    function_client1 = Function("client1_vlan")
    configlist.extend(function_client1.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))
    configlist.extend(function_client1.get_route(route_type, route_mode, "", "", gateway, "", "", "", ""))
    interface_client1 = Interface("client1_port")
    configlist.extend(interface_client1.get_port_interface(port_index, port_type, vlan_index, vlan_tagged, port_tagged))

    device.device_set_configs(configlist)


    checkitem = "client1_config"
    checkcommandlist = ["show interface all", "show interface vlan %s detail"%(vlan_index)]
    checkitemlist = ["vlan %s" % (vlan_index), "IP address : %s" % (ipaddress)]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger, device, checkitem, value, checkmatch)
        if result == False:
            return result

    return result

def Private_client_config(device):
    configlist = list()
    # set vlan
    vlan_index = 20
    vlan_description = "client2_vlan20"
    ip_mode = "static"
    ipaddress = "192.168.20.1"
    netmask = "255.255.255.0"
    #set port
    port_index = get_client_port_index(vlan_index)
    port_type = "port"
    vlan_tagged = "untagged"
    port_tagged = "untagged"
    # set route
    route_type = "ip"
    route_mode = "default"
    gateway = "192.168.20.254"
    result = False

    function_client2 = Function("client2_vlan")
    configlist.extend(function_client2.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))
    configlist.extend(function_client2.get_route(route_type, route_mode, "", "", gateway, "", "", "", ""))
    interface_client2 = Interface("client2_port")
    configlist.extend(interface_client2.get_port_interface(port_index, port_type, vlan_index, vlan_tagged, port_tagged))

    device.device_set_configs(configlist)

    checkitem = "client2_config"
    checkcommandlist = ["show interface all", "show interface vlan %s detail" % (vlan_index)]
    checkitemlist = ["vlan %s" % (vlan_index), "IP address : %s" % (ipaddress)]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger, device, checkitem, value, checkmatch)
        if result == False:
            return result

    return result

def Server_set_maintenance(device, server_maintenance_ip):
    configlist = list()
    #set maintence ip
    interface = Interface("maintenance_ip")
    configlist.extend(interface.get_maintenance_interface(server_maintenance_ip, "255.255.255.0"))
    device.device_set_configs(configlist)

    #check config
    checkitem = "server_set_maintenance"
    checkcommandlist = ["show interface maintenance 0 brief"]
    checkitemlist = ["IP address : %s"%(server_maintenance_ip)]
    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result =device_check_info(logger, device, checkitem, value, checkmatch)
        if result == False:
            return result

    return result

def Server_set_vlan_port(device):
    configlist = list()
    # set vlan and port
    vlan_index_list = [10, 20]
    vlan_description_list = ["server_vlan10", "server_vlan20"]
    ip_mode = "static"
    ipaddress_list = ["192.168.10.254", "192.168.20.254"]
    netmask = "255.255.255.0"
    port_index=get_server_port_list()
    port_type = "port"
    vlan_tagged = "untagged"
    port_tagged = "untagged"
    result = False
    for index, vlan_index in enumerate(vlan_index_list):
        function = Function("server_vlan")
        configlist.extend(function.get_vlan(vlan_index, vlan_description_list[index], ip_mode, ipaddress_list[index], netmask))
        interface = Interface("server_port")
        configlist.extend(interface.get_port_interface(port_index[index], port_type, vlan_index_list[index], vlan_tagged,port_tagged))

        device.device_set_configs(configlist)

        # check config
        checkitem = "server_set_vlan_port"
        checkcommandlist = ["show interface all", "show interface vlan %s detail" % (vlan_index_list[index])]
        checkitemlist = ["vlan %s" % (vlan_index_list[index]), "IP address : %s" % (ipaddress_list[index])]
        logger.info("[%s]Starting" % (checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            result =device_check_info(logger, device, checkitem, value, checkmatch)
            if result == False:
                return result
    return result

def set_dialer(device):
    configlist = list()
    # profile and dialer
    profile_name = "LTE"
    access_name = "internet"
    dialer_index = 0
    cellular_index = "0/1"
    if device.device_type == "sts":
        cellular_index = "0"
    result = False

    profile = Profile("Profile")
    configlist.extend(profile.get_cellular_profile(profile_name, access_name))
    interface_dialer = Interface("server_dialer")
    configlist.extend(interface_dialer.get_dialer_interface(dialer_index, profile_name, cellular_index))

    device.device_set_configs(configlist)

    time.sleep(20)
    checkitem = "server_set_dialer"
    checkcommandlist = ["show interface all", "show interface dialer %s detail" % (dialer_index)]
    checkitemlist = ["dialer %s" % (dialer_index), "Operational : up"]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result =device_check_info(logger, device, checkitem, value, checkmatch)
        if result == False:
            return result
    return result

def set_classifier(device):
    configlist = list()
    # classifier
    index_list = [10, 20]
    description_list = ["client1 to public network", "client2 to internal network"]
    ip_type = "source"
    protocol_type = ""
    port_mode = ""
    port_no = ""
    ip_address_list = ["192.168.10.0/24", "192.168.20.0/24"]
    result = False

    for index, classifier_index in enumerate(index_list):
        classifier = Function("Classifier")
        configlist.extend(classifier.get_classifier(index_list[index], description_list[index], ip_type, protocol_type, port_mode, port_no, ip_address_list[index]))

        device.device_set_configs(configlist)

        # check_config
        checkitem = "server_set_classifier"
        checkcommandlist = ["show classifier %s" % (index_list[index])]
        checkitemlist = ["Classifier ID : %s" % (index_list[index])]
        logger.info("[%s]Starting" % (checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            result =device_check_info(logger, device, checkitem, value, checkmatch)
            if result == False:
                return result
    return result

def Server_set_route_table(device):
    configlist = list()
    # route table
    route_type_1 = "table"
    route_mode_1 = "default "
    route_type_2 = "ip"
    route_mode_2 = "network"
    route_ip = "10.1.0.0"
    route_netmask = "255.255.0.0"
    gateway = ""
    interface = "maintenance 0"
    metric = ""
    table_index_list = [10, 20]
    classifier_index_list = [10, 20]
    priority_list = [1, 2]
    default_interface = ["dialer 0", "maintenance 0"]
    result = False

    for index, table in enumerate(table_index_list):
        route = Function("Route")
        configlist.extend(route.get_route(route_type_1, route_mode_1, "", "", "", "", metric, table_index_list[index], default_interface[index]))
        configlist.extend(route.get_route(route_type_2, route_mode_2, route_ip, route_netmask, gateway, interface, metric, "", ""))
        configlist.extend(route.get_policy_route(classifier_index_list[index], table_index_list[index], priority_list[index]))


        device.device_set_configs(configlist)

        # check_config
        checkitem = "server_route_table"
        checkcommandlist = ["show route table all"]
        #checkitemlist = ["%s" % (table_index_list[index])]
        checkitemlist = ["%s(.*)0.0.0.0(.*)0.0.0.0(.*)0.0.0.0(.*)S" % (table_index_list[index])]
        logger.info("[%s]Starting" % (checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            result = device_check_info(logger, device, checkitem, value, checkmatch)
            if result == False:
                return result
    return result

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
    #configlist.extend(profile.get_cellular_profile(profile1_name,access1_name))

    interface = Interface("Celluar")
    configlist.extend(interface.get_dialer_interface(dialer0_index,profile0_name,cellular0_index))
    #configlist.extend(interface.get_dialer_interface(dialer1_index,profile1_name,cellular1_index))
    device.device_set_configs(configlist)
    time.sleep(30)

    checkitem ="Pretesting_Cellular"   #"show cellular-profile" fail already fill JIRA
    checkcommandlist = ["show platform led","show interface all","show interface dialer %s detail"%(dialer0_index),"show sim-management current-status"
        ,"ping -I %s -c5 8.8.8.8"%(cellular0_usb_index)]#"show cellular-profile %s"%(profile0_name),

    checkitemlist = ["LTE%s (.*) green"%(cellular0_index),"dialer %s (.*) up"%(dialer0_index)
       ,"Operational : up | MTU : 1500","dialer %s (.*) %s (.*)"%(dialer0_index,dialer0_carrier),"64 bytes from 8.8.8.8: icmp_seq=5 (.*)"]#"Access Point Name (.*) %s"%(access0_name) ,

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result
    return result

    '''checkcommandlist = ["show cellular-profile %s"%(profile1_name),"show platform led","show interface all","show interface dialer %s detail"%(dialer1_index),"show sim-management current-status"
        ,"ping -I %s -c5 8.8.8.8"%(cellular1_usb_index)]
    checkitemlist = ["Access Point Name (.*) %s"%(access1_name) ,"LTE%s (.*) green"%(cellular1_index),"dialer %s (.*) up"%(dialer1_index)
       ,"Operational : up | MTU : 1500","dialer %s (.*) %s (.*)"%(dialer1_index,dialer1_carrier),"64 bytes from 8.8.8.8: icmp_seq=5 (.*)"]

    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)'''

def Pretesting_Wifi(device):
    configlist = list()
    sta_profile_name ="eap-peap"
    sta_ssid_name ="SQA-STA-EAP-2.4G"
    wlan1_index = 1
    wlan1_mode = "sta"
    wlan1_ip_mode="dhcp"
    ap_ssid_name="ATS2.0"


    #### wpa-eap setting.
    sta_key_type = "wpa-eap"
    sta_wpa_version = "2"
    sta_auth_type ="sta-eap"
    sta_eap_type ="peap"
    sta_eap_identity ="lance"
    sta_eap_password = "lance0124"

    profile = Profile("Wifi")
    configlist.extend(profile.get_wifi_profile(sta_profile_name,sta_ssid_name,sta_key_type
                                               ,sta_wpa_version,"",sta_auth_type))

    interface = Interface("wifi")
    configlist.extend(interface.get_wifi_interface(wlan1_index,sta_profile_name,wlan1_mode,wlan1_ip_mode))
    device.device_set_configs(configlist)

    checkitem ="Pretesting_Wifi_Station"

    checkcommandlist = ["show wifi-profile %s"%(sta_profile_name),"show platform led","show interface all"
        ,"show interface wlan %s detail"%(wlan1_index)]
    checkitemlist = ["SSID : %s | WPA PSK : %s"%(ap_ssid_name,sta_key_type),"WLAN%s (.*) green"%(wlan1_index),"wlan %s (.*) up"%(wlan1_index)
        ,"Operational : up | MTU : 1500"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result
    return result

def Tunnel_Basic(device,interface,controller_ip): # Tesitng  basic tunnel under udp mode over several uplink interfaces
    checkitem = "Interface_check for Tunnel"
    configlist = list()
    if device.device_type !="lmc":
        if interface=="dialer 0" or "dialer 1":
            pretest_result = set_dialer(device)#Pretesting_Cellular(device)
        elif interface =="maintenance 0":
            checkcommand = "show interface all"
            checkitemlist = "maintenance 0 (.*) up"
            pretest_result = device.device_send_command_match(checkcommand, 10, checkitemlist)
        elif interface =="wlan  0":
            pretest_result = Pretesting_Wifi(device)
    else:
        device.device_send_command("update terminal paging disable")#config host name R11_STS
        checkcommandlist = ["show interface all","show interface all","ping 8.8.8.8"]
        checkitemlist = ["eth 0 (.*) up", "%s (.*) up"%(interface),"64 bytes from 8.8.8.8: icmp_seq="]
        logger.info("[%s]Starting" % (checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            pretest_result = device_check_info(logger, device, checkitem, value, checkmatch)
            logger.info("[%s]LMC Interface init %s" % (checkitem,pretest_result))
    #print pretest_result
    if pretest_result:
        #print pretest_result
        logger.info("[%s]Interface init compelted" % (checkitem))
        logger.info("[%s]Setup Tunnel on UDP via %s" % (checkitem,interface))
        tunnel_session1 = Function("tunnel_1")
        configlist.extend(tunnel_session1.get_tunnel(device.device_type, "single", "udp", interface, "", controller_ip))
        print configlist
        device.device_set_configs(configlist)
        device.device_get_running_config

        if device.device_type != "lmc":
            checkitem = "tunnel1_config"
            checkcommandlist = ["show interface all", "show mobility tunnel all"]
            checkitemlist = ["%s (.*) up" %(interface), "%s (.*) UA" %(interface)]
            logger.info("[%s]Starting" % (checkitem))
            for index, value in enumerate(checkcommandlist):
                checkmatch = checkitemlist[index]
                result = device_check_info(logger, device, checkitem, value, checkmatch)
                if result == False:
                    return result
                time.sleep(120)
            return result
    else:
        logger.write("info", "Server Device Interface Faile")
        sys.exit(0)

        #print matchresult0
        #if matchresult0 == False:

def Tunnel_Check(device,controller_ip):

    "R11-STS1                           e4:2c:56:db:f8:20   0.0.0.0       TRUE"
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

if __name__ == '__main__':

    connecttype = "telnet"
    server_connecttype= "ssh"
    set_result = True

    #setup public(default google) ping and private(default SJ-router) ping ip for route test
    #Gobal Paramter
    public_ping_ip = "8.8.8.8"
    private_ping_ip = "10.1.2.1"
    controller_int_ip = "10.2.53.201"#"10.2.66.60"#
    controller_public_ip = "60.248.28.117"#"60.248.28.118"#

    #STS
    Server_Type = ""
    server_ip = "10.2.53.201"
    server_port = 22
    server_maintenance_ip = "10.2.53.201"
    server_login_user ="admin"
    server_login_password ="Lilee1234"
    public_client_ip = "10.2.66.50"#"10.2.66.50"  # ssh ip 10.2.66.61  :
    public_client_port = 2038#2040
    #public_client_maintenance_ip = "10.2.66.64"#"10.2.66.65"
    #public_connect_type = "telnet"
    public_login_user = "admin"
    public_login_password = "admin"
    private_client_ip = "10.2.66.50" # ssh ip 10.2.66.64
    private_client_port =2040
    #private_client_maintenance_ip = "10.2.66.64"  # "10.2.66.65"
    private_login_user ="admin"
    private_login_password ="admin"
    if len(sys.argv) >2:

        LMC_info = sys.argv[1].split("_")  # ssh_10.2.53.201_22_admin_Lilee1234
        LMS_info = sys.argv[2].split("_")  # telnet_10.2.66.50_2038_admin_admin
        STS_info = sys.argv[3].split("_")  #  telnet_10.2.66.50_2040_admin_admin

        server_connect_type = LMC_info[0]
        server_ip = LMC_info[1]
        server_port = LMC_info[2]
        #server_maintenance_ip = Routing_Server_Info.split("_")[3]
        server_login_user =LMC_info[3]
        server_login_password = LMC_info[4]

        #public_client_Info = LMS_info[3]  # telnet_10.2.66.50_2038_admin_admin =>connecttype_ip_port_maintenceip_username_password
        public_connect_type = LMS_info[0]
        public_client_ip = LMS_info[1]
        public_client_port = LMS_info[2]
        public_login_user = LMS_info[3]
        public_login_password = LMS_info[4]

        #private_client_Info = sys.argv[4]  # telnet_10.2.66.50_2040_admin_admin =>connecttype_ip_port_maintenceip_username_password
        private_connect_type = STS_info[0]
        private_client_ip = STS_info[1]
        private_client_port = STS_info[2]
        private_login_user = STS_info[3]
        private_login_password = STS_info[4]



    #Routing Server set configuration
    server_device = Device_Tool(server_ip, server_port, server_connecttype, server_login_user, server_login_password, "Tunnel_test")
    #print "Test Start"
    if server_device.target:
        #logger.write("info", "Server Device type:%s" % (server_device.device_type))
        server_device.device_send_command("update terminal paging disable",10)
        server_device.device_get_version()
        server_device.device_get_hostname()
        #server_device.device_get_register_MAC("maintenance 0")
        logger.write("info","Server Device type:%s"%(server_device.device_type))
        logger.write("info","Server Device Bios Version:%s"%(server_device.bios_version))
        logger.write("info","Server Device recovery image:%s"%(server_device.boot_image))
        logger.write("info","Server Device build image:%s"%(server_device.build_image))
        logger.write("info","Server Device testrail image:%s"%(server_device.testrail_build_version))
        #logger.write("info","Server Device mac:%s"%(server_device.device_register_MAC))
        logger.write("info","Server Device hostname:%s"%(server_device.device_hostname))
        logger.write("info","Server Device version:%s"%(server_device.branch_version))

        Server_Type = server_device.device_type

    else:
        logger.write("info", "Server Login Failed")
        sys.exit(0)

    if server_device:
        Tunnel_Basic(server_device, "eth 1",controller_public_ip)
        set_result = True
    else:
        #print server_device
        logger.write("info", "Server Failed by %s"%(server_device))
        sys.exit(0)


    #Routing public client set configuration
    if set_result == True :
        public_client_device = Device_Tool(public_client_ip, public_client_port, connecttype, public_login_user, public_login_password, "Tunnel_test")
        if public_client_device.target:
            public_client_device.device_send_command("update terminal paging disable",10)
            public_client_device.device_get_version()
            public_client_device.device_get_hostname()
            public_client_device.device_get_register_MAC("maintenance 0")
            logger.write("info","Public Client type:%s"%(public_client_device.device_type))
            logger.write("info","Public Client Bios Version:%s"%(public_client_device.bios_version))
            logger.write("info","Public Client recovery image:%s"%(public_client_device.boot_image))
            logger.write("info","Public Client build image:%s"%(public_client_device.build_image))
            logger.write("info","Public Client testrail image:%s"%(public_client_device.testrail_build_version))
            logger.write("info","Public Client mac:%s"%(public_client_device.device_register_MAC))
            logger.write("info","Public Client hostname:%s"%(public_client_device.device_hostname))
            logger.write("info","Public Client version:%s"%(public_client_device.branch_version))

            #public_client_device.device_no_config()
            public_client_device.device_send_command("show version")
            public_client_device.device_send_command("config host name R11_%s"%(public_client_device.device_type))
            #set_result =Public_client_config(public_client_device)
            if public_client_device:
                Tunnel_Basic(public_client_device, "dialer 0",controller_public_ip)
                Tunnel_Basic(public_client_device, "maintenance 0", controller_int_ip)
            else:
                logger.write("info", "Public_Client Failed by %s" % (public_client_device))
                sys.exit(0)
        else:
            logger.write("info", "Public_Client Login Failed")
            sys.exit(0)
        private_client_device = Device_Tool(private_client_ip, private_client_port, connecttype, private_login_user, private_login_password, "Tunnel_test")
        if private_client_device.target:
            private_client_device.device_send_command("update terminal paging disable",10)
            private_client_device.device_get_version()
            private_client_device.device_get_hostname()
            private_client_device.device_get_register_MAC("maintenance 0")
            logger.write("info","Private Client type:%s"%(private_client_device.device_type))
            logger.write("info","Private Client Bios Version:%s"%(private_client_device.bios_version))
            logger.write("info","Private Client recovery image:%s"%(private_client_device.boot_image))
            logger.write("info","Private Client build image:%s"%(private_client_device.build_image))
            logger.write("info","Private Client testrail image:%s"%(private_client_device.testrail_build_version))
            logger.write("info","Private Client mac:%s"%(private_client_device.device_register_MAC))
            logger.write("info","Private Client hostname:%s"%(private_client_device.device_hostname))
            logger.write("info","Private Client version:%s"%(private_client_device.branch_version))

            #public_client_device.device_no_config()
            #public_client_device.device_send_command("config switch port 0 disable")
            private_client_device.device_send_command("show version")
            private_client_device.device_send_command("config host name R11_%s"%(private_client_device.device_type))
            #set_result =Public_client_config(public_client_device)
            if private_client_device:
                Tunnel_Basic(private_client_device, "dialer 0",controller_public_ip)
                Tunnel_Basic(private_client_device, "maintenance 0", controller_int_ip)

            else:
                logger.write("info", "Private_client Login Failed")
                sys.exit(0)