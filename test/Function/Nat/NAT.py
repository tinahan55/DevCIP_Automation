__author__ = 'mandy.wu'
from lib.Device import *
from lib.Configuration import *
import os
from time import gmtime, strftime
from lib.SSHConsole import *



#def NAT_port_setup(include port and app-engine)
#def dhcp_setup
#dnat

logger = Log("NAT_test","NAT_test")

def get_server_port():
    port_array = "2/2"
    if  "LMS" in Server_Type:
        port= "2/2"
    elif "DTS" in Server_Type:
        port="2"
    elif "STS" in Server_Type:
         port="2"
    return port

def get_client_port_index(vlan_index):
    port_index = "1"
    if "LMS" in Server_Type:
            port_index = "2"
    elif "DTS" in Server_Type:
            port_index = "3"
    elif "STS" in Server_Type:
            port_index = "2/2"
    return port_index


def get_appengine_port():
        port = "0"
        if  "LMS" in Server_Type:
            port= "4"
        elif "DTS" in Server_Type:
            port="0"
        elif "STS" in Server_Type:
            port="0"
        return port

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

def SNAT_Server_set_maintenance(device, server_maintenance_ip):
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

def SNAT_Server_set_vlan_port(device):
    configlist = list()
    # set vlan and port
    vlan_index= 20
    vlan_description = "server_vlan20"
    ip_mode = "static"
    ipaddress = "192.168.20.254"
    netmask = "255.255.255.0"
    port_index=get_server_port()
    port_type = "port"
    vlan_tagged = "untagged"
    port_tagged = "untagged"
    result = False

    function = Function("server_vlan")
    configlist.extend(function.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))
    interface = Interface("server_port")
    configlist.extend(interface.get_port_interface(port_index, port_type, vlan_index, vlan_tagged,port_tagged))
    device.device_set_configs(configlist)

    # check config
    checkitem = "server_set_vlan_port"
    checkcommandlist = ["show interface all", "show interface vlan %s detail" % (vlan_index)]
    checkitemlist = ["vlan %s" % (vlan_index), "IP address : %s" % (ipaddress)]
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
    route_type = "ip"
    route_mode = "network"
    route_ip = "10.2.0.0"
    route_netmask = "255.255.0.0"
    gateway = ""
    interface = "maintenance 0"
    result = False
    route = Function("Route")
    configlist.extend(route.get_route(route_type, route_mode, route_ip, route_netmask, gateway, interface, "", "", ""))

    device.device_set_configs(configlist)

    # check_config
    checkitem = "server_route_"
    checkcommandlist = ["show route"]
    checkitemlist = ["%s(.*)%s(.*)S(.*)%s" % (route_ip,route_netmask,interface)]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            result = device_check_info(logger, device, checkitem, value, checkmatch)
            if result == False:
                return result
    return result

def SNAT_client_config(device):
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

def DNAT_Server_set_vlan_port(device):
    configlist = list()
    # port
    port_type = "port"
    vlan_index = 100
    port_index = 1
    vlan_tagged = "untagged"
    port_tagged = "untagged"

    #vlan
    ip_mode = "static"
    ipaddress = "10.1.4.254"
    netmask = "255.255.255.0"
    vlan_description = "DNAT-test"
    result =False

    interface = Interface("Port")
    configlist.extend(interface.get_port_interface(port_index,port_type,vlan_index,vlan_tagged,port_tagged))

    function = Function("vlan")
    configlist.extend(function.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))

    device.device_set_configs(configlist)

    #verify command
    checkitem = "NAT_port_setup"
    checkcommandlist = ["show interface all", "show interface vlan %s detail"%(vlan_index)]

    checkitemlist = ["vlan %s"%(vlan_index), "Operational : up | MTU : 1500"]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result

    return result

def DNAT_Server_app_engine_setup(device):
    configlist = list()
    # app-engine
    port_type = "app-engine"
    vlan_index = 100
    vlan_tagged = "untagged"

    port_index = get_appengine_port()
    port_tagged = "untagged"
    result =False


    interface = Interface("app-engine")
    configlist.extend(interface.get_port_interface(port_index,port_type,vlan_index,vlan_tagged,port_tagged))

    device.device_set_configs(configlist)


    device.device_send_command("config app-engine %s enable"%(port_index),30)

    time.sleep(20)

    #verfiy command
    checkitem = "NAT_app_engine_setup"
    checkcommandlist = ["show app-engine %s info"%(port_index)]

    checkitemlist = ["Operational : Running"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result
    return result

def DNAT_Server_dhcp(device):
    configlist = list()
    pool_name = "test-dhcp"
    pool_start_ip = "10.1.4.153"
    pool_end_ip = "10.1.4.153"
    netmask = "255.255.255.0"
    default_gateway = "10.1.4.254"
    dns_server_list = ["168.95.1.1"]
    dns_priority_list =[1]
    dhcp_interface = "vlan 100"
    result =False


    function = Function("dhcp")
    configlist.extend(function.get_dhcp_pool(pool_name, pool_start_ip, pool_end_ip, netmask, default_gateway))
    configlist.extend(function.set_dhcp_pool_dns(pool_name, dns_server_list, dns_priority_list))
    configlist.extend(function.set_dhcp_pool_interface(pool_name,dhcp_interface))
    configlist.extend(function.get_service("dhcp-server"))


    device.device_set_configs(configlist)

    #add verify command
    checkitem = "NAT_dhcp"
    checkcommandlist = ["show dhcp-server lease"]

    checkitemlist = ["%s"%(pool_start_ip)]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result
    return result


def DNAT_Server_classifier(device):
    configlist = list()
    index = 100
    description = "automatically added for port forwarding"
    ip_type = "protocol"
    protocol_type = "tcp"
    port_mode = "dport"
    port_no = 2222
    ip_address = "10.1.4.226"
    result =False


    function = Function("classifier")
    configlist.extend(function.get_classifier(index,description,ip_type, protocol_type, port_mode, port_no,ip_address))

    device.device_set_configs(configlist)

    #add verify command
    checkitem = "NAT_classifier"
    checkcommandlist = ["show classifier %s"%(index)]

    checkitemlist = ["Classifier ID : %s"%(index), "Protocol : %s"%(protocol_type)]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result

    return result


def DNAT_Server(device):
    configlist = list()
    nat_type = "dnat"
    port = 22
    interface = "maintenance 0"
    classifier_index = 100
    ip = "10.1.4.153"
    priority = 1
    result =False


    function = Function("NAT")
    configlist.extend(function.get_nat(nat_type, port, interface, classifier_index, ip, priority))

    device.device_set_configs(configlist)

    #add verify command
    checkitem = "NAT"
    checkcommandlist = ["show %s"%(nat_type)]

    checkitemlist = ["%s"%(ip)]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger,device,checkitem,value,checkmatch)
        if result == False:
            return result

    return result


#main( connect -> initial setup -> catch config -> compare -> append config -> show and verify)
if __name__ == '__main__':
    connecttype = "telnet"
    set_result = True
    Target_ping_ip = "10.2.10.17"

    #STS
    Server_Type = "LMS"
    Client_Type ="STS" #client port 2/2 =>server port 2
    server_ip = "10.2.66.50" # ssh ip 10.2.66.65
    server_port = 2038
    server_maintenance_ip = "10.2.66.64"
    server_login_user ="admin"
    server_login_password ="admin"
    client_ip = "10.2.66.50" # ssh ip 10.2.66.64
    client_port =2040
    client_login_user ="admin"
    client_login_password ="admin"
    if len(sys.argv) >3:
        connect_type = sys.argv[1]
        Server_Info = sys.argv[2] #telnet_10.2.66.50_2040_10.2.66.61_admin_admin =>connecttype_ip_port_maintenceip_username_password
        server_connect_type = Server_Info.split("_")[0]
        server_ip =Server_Info.split("_")[1]
        server_port =Server_Info.split("_")[2]
        server_maintenance_ip = Server_Info.split("_")[3]
        server_login_user = Server_Info.split("_")[4]
        server_login_password = Server_Info.split("_")[5]

        client_Info=sys.argv[3]#telnet_10.2.66.50_2038_admin_admin =>connecttype_ip_coport_maintenceip_username_password
        connect_type = client_Info.split("_")[0]
        client_ip =client_Info.split("_")[1]
        client_port =client_Info.split("_")[2]
        login_user = client_Info.split("_")[3]
        login_password = client_Info.split("_")[4]

    #SNAT Server set configuration
    logger.info("SNAT and DNAT Testing")
    server_device = Device_Tool(server_ip, server_port, connecttype, server_login_user, server_login_password, "NAT_test")
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

        logger.info("[SNAT]Server clear the configuration ...")
        server_device.device_no_config()

        logger.info("[SNAT]Server set the configuration ...")
        server_device.device_send_command("config switch port 0 disable")
        set_result = SNAT_Server_set_maintenance(server_device,server_maintenance_ip)
        if set_result == True : set_result =SNAT_Server_set_vlan_port(server_device)
        if set_result == True : set_result =Server_set_route_table(server_device)

        logger.info("[SNAT]Server show the configuration ...")
        logger.info("[SNAT] %s"%(server_device.device_get_running_config()))


    #SNAT client set configuration
    if set_result == True :
        client_device = Device_Tool(client_ip, client_port, connecttype, client_login_user, client_login_password, "NAT_test")
        if client_device.target:
            client_device.device_send_command("update terminal paging disable",10)
            client_device.device_get_version()
            client_device.device_get_hostname()
            client_device.device_get_register_MAC("maintenance 0")
            logger.write("info","Client type:%s"%(client_device.device_type))
            logger.write("info","Client Bios Version:%s"%(client_device.bios_version))
            logger.write("info","Client recovery image:%s"%(client_device.boot_image))
            logger.write("info","Client build image:%s"%(client_device.build_image))
            logger.write("info","Client testrail image:%s"%(client_device.testrail_build_version))
            logger.write("info","Client mac:%s"%(client_device.device_register_MAC))
            logger.write("info","Client hostname:%s"%(client_device.device_hostname))
            logger.write("info","Client version:%s"%(client_device.branch_version))

            logger.info("[SNAT]Client clear the configuration ...")
            client_device.device_no_config()


            logger.info("[SNAT]Client set the configuration ...")
            client_device.device_send_command("config switch port 0 disable")
            set_result =SNAT_client_config(client_device)


            logger.info("[SNAT]Client show the configuration ...")
            logger.info("[SNAT] %s"%(client_device.device_get_running_config()))



    if set_result == True :
        time.sleep(10)
        #SNAT ping testing
        logger.info( "[SNAT]ping testing start...")
        server_command = "tcpdump -c5 -i eth1 icmp"
        server_command_match = "%s: ICMP echo request"%(Target_ping_ip)
        client_command = "ping -c10 %s"%(Target_ping_ip)
        server_device.device_send_command("config snat out-interface maintenance 0 priority 1",5)
        client_device.device_send_command("no config interface maintenance 0 enable",5)
        time.sleep(10)

        client_device.device_send_command(client_command,2)
        matchresult = server_device.device_send_command_match(server_command,20,server_command_match)
        if matchresult ==True :
            logger.info("[SNAT] test by maintenance successful!!")
        else:
            logger.info("[SNAT] test by maintenance  fail!!")


        #Dnat client set configuration
        logger.info("[DNAT]Server clear the configuration ...")
        server_device.device_no_config()
        logger.info("[DNAT]Server set the configuration ...")
        set_result =DNAT_Server_set_vlan_port(server_device)
        if set_result == True : set_result =DNAT_Server_app_engine_setup(server_device)
        if set_result == True : set_result =DNAT_Server_dhcp(server_device)
        if set_result == True : set_result =DNAT_Server_classifier(server_device)
        if set_result == True : set_result =DNAT_Server(server_device)
        if set_result == True : set_result =Server_set_route_table(server_device)
        if set_result == True :
            time.sleep(60)
            #DNAT ssh testing by port
            logger.info("[DNAT]ssh login to test ...")
            dnat_device = Device_Tool(server_maintenance_ip, 2222, "ssh", "root", "admin", "NAT_test")
            #dnat_device = Device_Tool(server_maintenance_ip, 2222, "ssh", "root", "Lilee1234", "NAT_test")
            if dnat_device.target:
                matchresult = dnat_device.device_send_command_match("ifconfig -a",20,"inet 10.1.4.153")
                if matchresult ==True :
                    logger.info("DNAT test by maintenance successful!!")
                else:
                    logger.info("DNAT test by maintenance  fail!!")


