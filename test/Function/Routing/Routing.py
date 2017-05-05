__author__ = 'mandy.wu'
__Reviewer__ ='Ricky.Wang'

from lib.Configuration import *
from lib.Device import *
import os
from lib.TelnetConsole import *

Server_Type = "STS"
logger = Log("Routing_test","Routing_test")


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

def Server_set_dialer(device):
    configlist = list()
    # profile and dialer
    profile_name = "LTE"
    access_name = "internet"
    dialer_index = 0
    cellular_index = "0/1"
    if 'STS' in Server_Type: cellular_index = "0"
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

def Server_set_classifier(device):
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

    #We have 1 server and 2 clients in this architecture
    #server --> do routing work
    #client1 --> public route testing
    #client2 --> private route testing

    #profile setup start---------------------------------------------------------
    #choose connecttype, "telnet" or "ssh"
    connecttype = "telnet"
    set_result = True

    #setup public(default google) ping and private(default SJ-router) ping ip for route test
    #Gobal Paramter
    public_ping_ip = "8.8.8.8"
    private_ping_ip = "10.1.2.1"

    '''
     #LMS
    Server_Type = "LMS"
    Public_Client_Type = "DTS" #client port 2/1 map server port 1
    Public_Client_Type ="STS" #client port 3 map server port 2
    server_ip = "10.2.66.50" # ssh ip 10.2.66.65
    server_port = 2038
    server_connect_type = "telnet"
    server_maintenance_ip = "10.2.66.64"
    server_login_user ="admin"
    server_login_password ="admin"

    public_connect_type = "telnet"
    public_client_ip = "10.2.66.50" # ssh ip 10.2.66.61
    public_client_port =2035
    public_login_user ="admin"
    public_login_password ="admin"

    private_connect_type = "telnet"
    private_client_ip = "10.2.66.50" # ssh ip 10.2.66.64
    private_client_port =2040
    private_login_user ="admin"
    private_login_password ="admin"


    #DTS
    Server_Type = "DTS"
    Public_Client_Type = "LMS" #client port 2/1 map server port 1
    Public_Client_Type ="STS" #client port 3 map server port 2
    server_ip = "10.2.66.50" # ssh ip 10.2.66.65
    server_port = 2035
    server_login_user ="admin"
    server_login_password ="admin"
    server_maintenance_ip = "10.2.66.61"
    public_client_ip = "10.2.66.50" # ssh ip 10.2.66.61
    public_client_port =2038
    public_login_user ="admin"
    public_login_password ="admin"
    private_client_ip = "10.2.66.50" # ssh ip 10.2.66.64
    private_client_port =2040
    private_login_user ="admin"
    private_login_password ="admin"

    '''
    #STS
    Server_Type = "STS"
    Public_Client_Type = "DTS" #client port 2 => server port 3
    Public_Client_Type ="LMS" #client port 2/2 =>server port 2
    server_ip = "10.2.66.50" # ssh ip 10.2.66.65
    server_port = 2040
    server_maintenance_ip = "10.2.66.65"
    server_login_user ="admin"
    server_login_password ="admin"
    public_client_ip = "10.2.66.50" # ssh ip 10.2.66.61
    public_client_port =2035
    public_login_user ="admin"
    public_login_password ="admin"
    private_client_ip = "10.2.66.50" # ssh ip 10.2.66.64
    private_client_port =2038
    private_login_user ="admin"
    private_login_password ="admin"
    if len(sys.argv) >3:
        connect_type = sys.argv[1]
        Routing_Server_Info = sys.argv[2] #telnet_10.2.66.50_2040_10.2.66.61_admin_admin =>connecttype_ip_port_maintenceip_username_password
        server_connect_type = Routing_Server_Info.split("_")[0]
        server_ip =Routing_Server_Info.split("_")[1]
        server_port =Routing_Server_Info.split("_")[2]
        server_maintenance_ip = Routing_Server_Info.split("_")[3]
        server_login_user = Routing_Server_Info.split("_")[4]
        server_login_password = Routing_Server_Info.split("_")[5]

        public_client_Info=sys.argv[3]#telnet_10.2.66.50_2035_admin_admin =>connecttype_ip_port_maintenceip_username_password
        public_connect_type = public_client_Info.split("_")[0]
        public_client_ip =public_client_Info.split("_")[1]
        public_client_port =public_client_Info.split("_")[2]
        public_login_user = Routing_Server_Info.split("_")[3]
        public_login_password = Routing_Server_Info.split("_")[4]

        private_client_Info=sys.argv[4]#telnet_10.2.66.50_2038_admin_admin =>connecttype_ip_port_maintenceip_username_password
        private_connect_type = private_client_Info.split("_")[0]
        private_client_ip =private_client_Info.split("_")[1]
        private_client_port =private_client_Info.split("_")[2]
        private_login_user = Routing_Server_Info.split("_")[3]
        private_login_password = Routing_Server_Info.split("_")[4]


    #Routing Server set configuration
    server_device = Device_Tool(server_ip, server_port, connecttype, server_login_user, server_login_password, "Routing_test")
    if server_device.target:
        server_device.device_send_command("update terminal paging disable",10)
        server_device.device_get_version()
        server_device.device_get_hostname()
        server_device.device_get_register_MAC("maintenance 0")
        logger.write("info","Server Device type:%s"%(server_device.device_type))
        logger.write("info","Server Device Bios Version:%s"%(server_device.bios_version))
        logger.write("info","Server Device recovery image:%s"%(server_device.boot_image))
        logger.write("info","Server Device build image:%s"%(server_device.build_image))
        logger.write("info","Server Device testrail image:%s"%(server_device.testrail_build_version))
        logger.write("info","Server Device mac:%s"%(server_device.device_register_MAC))
        logger.write("info","Server Device hostname:%s"%(server_device.device_hostname))
        logger.write("info","Server Device version:%s"%(server_device.branch_version))

        Server_Type = server_device.device_product_name
        server_device.device_no_config()

        server_device.device_send_command("config switch port 0 disable")
        set_result = Server_set_maintenance(server_device,server_maintenance_ip)
        if set_result == True : set_result =Server_set_vlan_port(server_device)
        if set_result == True : set_result =Server_set_dialer(server_device)
        if set_result == True : set_result =Server_set_classifier(server_device)
        if set_result == True : set_result =Server_set_route_table(server_device)


    #Routing public client set configuration
    if set_result == True :
        public_client_device = Device_Tool(public_client_ip, public_client_port, connecttype, public_login_user, public_login_password, "Routing_test")
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

            public_client_device.device_no_config()
            public_client_device.device_send_command("config switch port 0 disable")

            set_result =Public_client_config(public_client_device)


    #Routing public client set configuration
    if set_result == True :
        private_client_device = Device_Tool(private_client_ip, private_client_port, connecttype, private_login_user, private_login_password, "Routing_test")
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


            private_client_device.device_no_config()
            private_client_device.device_send_command("config switch port 0 disable")

            set_result = Private_client_config(private_client_device)

    if set_result == True :
        #Routing public ping testing
        print "Routing public ping testing start..."
        public_server_command = "tcpdump -c5 -i usb1 icmp"
        public_server_command_match = "%s: ICMP echo request"%(public_ping_ip)
        client_command = "ping -c10 %s"%(public_ping_ip)
        public_client_device.device_send_command("no config interface maintenance 0 enable",5)
        server_device.device_send_command("config snat out-interface dialer 0 priority 1",5)
        public_client_device.device_send_command(client_command,2)
        matchresult = server_device.device_send_command_match(public_server_command,20,public_server_command_match)

        if matchresult ==True :
            print "public routing test successful!!"
        else:
            print "public routing test fail!!"

        #Routing private ping testing
        print "Routing private ping testing start..."
        private_server_command = "tcpdump -c5 -i eth0 icmp"
        private_server_command_match = "%s: ICMP echo request"%(private_ping_ip)
        client_command = "ping -c10 %s"%(private_ping_ip)
        private_client_device.device_send_command("no config interface maintenance 0 enable",5)
        server_device.device_send_command("config snat out-interface maintenance 0 priority 1",5)
        private_client_device.device_send_command(client_command,2)
        matchresult = server_device.device_send_command_match(private_server_command,20,private_server_command_match)

        if matchresult ==True :
            print "private routing test successful!!"
        else:
            print "private routing test fail!!"
