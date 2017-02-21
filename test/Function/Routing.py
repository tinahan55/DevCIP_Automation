__author__ = 'mandy.wu'
from lib.Configuration import *
from lib.Device import *
import os
from time import gmtime, strftime
from lib.TelnetConsole import *


def device_check_info(logger, device, checkitem, checkcommand, checkmatch):
        title = "[%s][%s]"%(checkitem, checkcommand)
        logger.info("%s starting"%(title))
        checkresult = device.device_send_command_match(checkcommand, 5, checkmatch)
        logger.info("%s check %s result: %s"%(title, checkmatch, checkresult))
        if checkresult == False:
            logger.info("%s check %s error: %s"%(title, checkmatch, device.target_response))

def DTS_config(device_DTS):
        configlist = list()
        #vlan
        vlan_index = 10
        vlan_description = "DTS_vlan10"
        ip_mode = "static"
        ipaddress = "192.168.10.1"
        netmask = "255.255.255.0"
        #port
        port_index = 1
        port_type = "port"
        vlan_tagged = "untagged"
        port_tagged = "untagged"

        function_dts = Function("DTS_vlan")
        configlist.extend(function_dts.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))
        interface_dts = Interface("DTS_port")
        configlist.extend(interface_dts.get_port_interface(port_index,port_type,vlan_index,vlan_tagged,port_tagged))
        device_DTS.device_set_configs(configlist)

        checkitem = "DTS_config"
        checkcommandlist = ["show interface all", "show interface vlan %s detail"%(vlan_index)]
        checkitemlist = ["vlan %s"%(vlan_index), "IP address : %s"%(ipaddress)]
        logger.info("[%s]Starting"%(checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger,device_DTS,checkitem,value,checkmatch)

def STS_config(device_STS):
        configlist = list()
        #vlan
        vlan_index = 20
        vlan_description = "STS_vlan10"
        ip_mode = "static"
        ipaddress = "192.168.20.1"
        netmask = "255.255.255.0"
        #port
        port_index = 2
        port_type = "port"
        vlan_tagged = "untagged"
        port_tagged = "untagged"

        function_sts = Function("STS_vlan")
        configlist.extend(function_sts.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))
        interface_sts = Interface("STS_port")
        configlist.extend(interface_sts.get_port_interface(port_index,port_type,vlan_index,vlan_tagged,port_tagged))

        device_STS.device_set_configs(configlist)

        checkitem = "STS_config"
        checkcommandlist = ["show interface all","show interface vlan %s detail"%(vlan_index)]
        checkitemlist = ["vlan %s"%(vlan_index), "IP address : %s"%(ipaddress)]
        logger.info("[%s]Starting"%(checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger, device_STS, checkitem, value, checkmatch)

def LMS_set_vlan_port(device_LMS):
        configlist = list()
        #vlan and port
        vlan_index_list = [10,20]
        vlan_description_list = ["LMS_vlan10","LMS_vlan20"]
        ip_mode = "static"
        ipaddress_list = ["192.168.10.254","192.168.20.254"]
        netmask = "255.255.255.0"
        port_index_list = ["2/1","2/2"]
        port_type = "port"
        vlan_tagged = "untagged"
        port_tagged = "untagged"

        for index, vlan_index in enumerate(vlan_index_list):
            function = Function("LMS_vlan")
            configlist.extend(function.get_vlan(vlan_index, vlan_description_list[index], ip_mode, ipaddress_list[index], netmask))
            interface = Interface("LMS_port")
            configlist.extend(interface.get_port_interface(port_index_list[index], port_type, vlan_index_list[index], vlan_tagged, port_tagged))


            device_LMS.device_set_configs(configlist)

            # check_config
            checkitem = "LMS_set_vlan_port"
            checkcommandlist = ["show interface all", "show interface vlan %s detail"%(vlan_index_list[index])]
            checkitemlist = ["vlan %s"%(vlan_index_list[index]), "IP address : %s"%(ipaddress_list[index])]
            logger.info("[%s]Starting" % (checkitem))
            for index, value in enumerate(checkcommandlist):
                checkmatch = checkitemlist[index]
                device_check_info(logger, device_LMS, checkitem, value, checkmatch)


        '''
                vlan_index_1 = 10
                vlan_index_2 = 20
                vlan_description_1 = "LMS_vlan10"
                vlan_description_2 = "LMS_vlan20"
                ip_mode = "static"
                ipaddress_1 = "192.168.10.254"
                ipaddress_2 = "192.168.20.254"
                netmask = "255.255.255.0"
                port_index_1 = "2/1"
                port_index_2 = "2/2"
                port_type = "port"
                vlan_tagged = "untagged"
                port_tagged = "untagged"

                function_lms_1 = Function("LMS_vlan_1")
                configlist.extend(function_lms_1.get_vlan(vlan_index_1, vlan_description_1, ip_mode, ipaddress_1, netmask))
                interface_lms_1 = Interface("LMS_port_1")
                configlist.extend(interface_lms_1.get_port_interface(port_index_1, port_type, vlan_index_1, vlan_tagged, port_tagged))

                function_lms_2 = Function("LMS_vlan_2")
                configlist.extend(function_lms_2.get_vlan(vlan_index_2, vlan_description_2, ip_mode, ipaddress_2, netmask))
                interface_lms_2 = Interface("LMS_port_2")
                configlist.extend(interface_lms_2.get_port_interface(port_index_2, port_type, vlan_index_2, vlan_tagged, port_tagged))
                '''

def LMS_set_dialer(device_LMS):
        configlist = list()
        #profile and dialer
        profile_name = "LTE"
        access_name = "internet"
        dialer_index = 0
        cellular_index = "0/1"

        profile = Profile("Profile")
        configlist.extend(profile.get_cellular_profile(profile_name, access_name))
        interface_dialer = Interface("LMS_dialer")
        configlist.extend(interface_dialer.get_dialer_interface(dialer_index, profile_name, cellular_index))

        device_LMS.device_set_configs(configlist)

        checkitem = "LMS_set_dialer"
        checkcommandlist = ["show interface all", "show interface dialer %s detail"%(dialer_index)]
        checkitemlist = ["dialer %s"%(dialer_index), "Operational : up"]
        logger.info("[%s]Starting"%(checkitem))
        for index, value in enumerate(checkcommandlist):
            checkmatch = checkitemlist[index]
            device_check_info(logger, device_LMS, checkitem, value, checkmatch)

def LMS_set_classifier(device_LMS):
        configlist= list()
        #classifier
        index_list = [10,20]
        description_list = ["DTS-1 to dialer","STS-1 to maintenance network"]
        ip_type = "source"
        protocol_type = 0
        port_mode = 0
        port_no = 0
        ip_address_list = ["192.168.10.0/24","192.168.20.0/24"]

        for index, classifier_index in enumerate(index_list):
            classifier = Function("Classifier")
            configlist.extend(classifier.get_classifier(index_list[index],description_list[index],ip_type, protocol_type, port_mode, port_no,ip_address_list[index]))

            device_LMS.device_set_configs(configlist)

            #check_config
            checkitem = "LMS_set_classifier"
            checkcommandlist = ["show classifier %s"%(index_list[index])]
            checkitemlist = ["Classifier ID : %s"%(index_list[index])]
            logger.info("[%s]Starting"%(checkitem))
            for index, value in enumerate(checkcommandlist):
                checkmatch = checkitemlist[index]
                device_check_info(logger, device_LMS, checkitem, value, checkmatch)


        '''
                index_1 = 10
                index_2 = 20
                description_1 = "DTS-1 to dialer"
                description_2 = "STS-1 to maintenance network"
                ip_type = "source"
                protocol_type = 0
                port_mode = 0
                port_no = 0
                ip_address_1 = "192.168.10.0/24"
                ip_address_2 = "192.168.20.0/24"

                classifier_10 = Function("Classifier_10")
                configlist.extend(classifier_10.get_classifier(index_1, description_1, ip_type, protocol_type, port_mode, port_no,ip_address_1))
                classifier_20 = Function("Classifier_20")
                configlist.extend(classifier_20.get_classifier(index_2, description_2, ip_type, protocol_type, port_mode, port_no,ip_address_2))
                '''

def LMS_set_route_table(device_LMS):
        configlist = list()
        #route table
        route_type = "table"
        route_mode = "default "
        route_ip = 0
        route_netmask = 0
        gateway_list = ["100.92.6.80","10.2.66.1"]
        interface = 0
        metric = 0
        table_index_list = [10,20]
        classifier_index_list = [10,20]
        priority_list = [1,2]

        for index, gateway in enumerate(gateway_list):
            route = Function("Route")
            configlist.extend(route.get_route(route_type, route_mode, route_ip, route_netmask, gateway_list[index], interface, metric, table_index_list[index], classifier_index_list[index], priority_list[index]))

            device_LMS.device_set_configs(configlist)

            #check_config
            checkitem = "LMS_route_table"
            checkcommandlist = ["show route table all"]
            checkitemlist = ["%s"%(table_index_list[index])]
            logger.info("[%s]Starting"%(checkitem))
            for index, value in enumerate(checkcommandlist):
                checkmatch = checkitemlist[index]
                device_check_info(logger, device_LMS, checkitem, value, checkmatch)



        '''
                route_type = "table"
                route_mode = "default "
                route_ip = 0
                route_netmask = 0
                gateway_1 = "10.27.31.151"
                gateway_2 = "10.27.31.151"
                interface = 0
                metric = 0
                table_index_1 = 10
                table_index_2 = 20
                classifier_index_1 = 10
                priority_1 = 1
                classifier_index_2 = 20
                priority_2 = 2

                route_1 = Function("Route_1")
                configlist.extend(route_1.get_route(route_type, route_mode, route_ip, route_netmask, gateway_1, interface, metric, table_index_1, classifier_index_1, priority_1))
                route_2 = Function("Route_2")
                configlist.extend(route_2.get_route(route_type, route_mode, route_ip, route_netmask, gateway_2, interface, metric, table_index_2, classifier_index_2, priority_2))
                '''




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

    logfilename = "Routing%s.log"%((strftime("%Y%m%d%H%M", gmtime())))
    logger = set_log(logfilename, "Routing_test")

    device_DTS = Device_Tool('10.2.66.50', 2035, "telnet", "admin", "admin", "Routing_test")
    if device_DTS:
        print "DTS connected"
        DTS_config(device_DTS)


    device_STS = Device_Tool('10.2.66.50', 2040, "telnet", "admin", "admin", "Routing_test")
    if device_STS:
        print "STS connected"
        STS_config(device_STS)


    device_LMS = Device_Tool('10.2.66.50', 2038, "telnet", "admin", "admin", "Routing_test")
    if device_LMS:
        print "LMS connected"
        LMS_set_vlan_port(device_LMS)
        LMS_set_dialer(device_LMS)
        LMS_set_classifier(device_LMS)
        LMS_set_route_table(device_LMS)




    #public route test
    print "public route test starting"
    TelnetConsole_DTS = Telnet_Console('10.2.66.50', 2035, "admin", "admin", "Routing_test")
    TelnetConsole_DTS.login()
    if TelnetConsole_DTS:
        TelnetConsole_DTS.send_command("no config interface maintenance 0 enable", 5, "lilee",checkResponse="localdomain", logflag=True)
        TelnetConsole_DTS.send_command("ping 8.8.8.8",5,"lilee",checkResponse="localdomain",logflag = True)

    TelnetConsole_LMS = Telnet_Console('10.2.66.50', 2038, "admin", "admin", "Routing_test")
    TelnetConsole_LMS.login()
    if TelnetConsole_LMS:
        TelnetConsole_LMS.send_command("tcpdump -i usb1 icmp", 5, "shell", checkResponse="bash-4.2#", logflag=True)
        TelnetConsole_LMS.telnet.write(("\x03").encode('ascii'))



    #internal route test
    print "internal route test starting"
    TelnetConsole_STS = Telnet_Console('10.2.66.50', 2040, "admin", "admin", "Routing_test")
    TelnetConsole_STS.login()
    if TelnetConsole_STS:
        TelnetConsole_STS.send_command("no config interface maintenance 0 enable",5,"lilee",checkResponse="localdomain",logflag = True)
        TelnetConsole_STS.send_command("ping 10.2.66.1",5,"lilee",checkResponse="localdomain",logflag = True)


    TelnetConsole_LMS = Telnet_Console('10.2.66.50', 2038, "admin", "admin", "Routing_test")
    TelnetConsole_LMS.login()
    if TelnetConsole_LMS:
        TelnetConsole_LMS.send_command("tcpdump -i eth0 icmp",5,"shell",checkResponse="bash-4.2#",logflag = True)
        TelnetConsole_LMS.telnet.write(("\x03").encode('ascii'))




