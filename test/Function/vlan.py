from lib.Device import *
from lib.Configuration import *
import logging
import os
from time import gmtime, strftime
from Config.function import *



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


def device_check_info(logger,device,checkitem,checkcommand,checkmatch):
    title = "[%s][%s]"%(checkitem,checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand,5,checkmatch)
    logger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
    if checkresult== False:
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))




if __name__ == '__main__':
    logfilename = "Vlan%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"Vlan_Testing")
    ip ="192.168.11.114"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"

    device =Device_Tool(ip,port,mode,username,password,"Vlan_Testing")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")

        configlist =list()

        #vlan
        vlan_list = [100,10]
        vlan_ip_mode_list = ["static","static"]
        vlan_ip_address_list = ["100.100.100.1","192.168.10.1"]
        vlan_pool_start_ip_list = ["100.100.100.100","192.168.10.100"]
        vlan_pool_end_ip_list = ["100.100.100.199","192.168.10.199"]
        vlan_pool_netmask = "255.255.255.0"
        vlan_netmask = "255.255.255.0"
        vlan_description = "NAT-test"
        vlan_pool_flag_list = [True,True]
        vlan_dns_list =["8.8.8.8","168.95.1.1"]
        vlan_dns_prority_list = ["2","1"]

        #port
        port_index_list = [1,2,0]
        port_type_list = ["port","port","app-engine 0 port "]
        port_vlan_index = [100,100,10]
        port_vlan_tagged = ["untagged","tagged","untagged"]
        port_port_tagged = ["untagged","tagged","untagged"]


        for index, vlan_index in enumerate(vlan_list):
            vlan_ip_mode = vlan_ip_mode_list[index]
            vlan_ip_address = vlan_ip_address_list[index]
            vlan_pool_flag = vlan_pool_flag_list[index]
            vlan_config =vlan(vlan_index,vlan_description,vlan_ip_mode,vlan_ip_address,vlan_netmask)
            if vlan_pool_flag == True:
                vlan_pool_name = "VLANPool%s"%(vlan_index)
                vlan_pool_start_ip = vlan_pool_start_ip_list[index]
                vlan_pool_end_ip = vlan_pool_end_ip_list[index]
                vlan_pool_default_gateway = vlan_ip_address
                vlan_config.get_dhcppool_vlan(vlan_pool_name,vlan_pool_start_ip,vlan_pool_end_ip,vlan_pool_netmask,vlan_pool_default_gateway
                                              ,vlan_dns_list,vlan_dns_prority_list)
            for index, port_vlan in enumerate(port_vlan_index):
                if vlan_index == port_vlan:
                    port_type =port_type_list[index]
                    port_index = port_index_list[index]
                    port_index = port_index_list[index]
                    porttagged = port_port_tagged[index]
                    vlantagged = port_vlan_tagged[index]
                    if port_type =="port":
                        vlan_config.get_port_vlan(port_index,porttagged,vlantagged)
                    else:
                        vlan_config.get_appengine_vlan(porttagged,vlantagged)

            configlist.extend(vlan_config.configlist)


        function = Function("dhcppool")
        configlist.extend(function.get_service("dhcp-server"))


        device.device_set_no_config(configlist)


        device.device_set_configs(configlist)


        time.sleep(10)


        # check interface vlan status
        for index, vlan_index in enumerate(vlan_list):
            vlan_ip_mode = vlan_ip_mode_list[index]
            vlan_ip_address = vlan_ip_address_list[index]
            checkcommandlist =["show interface all","show interface vlan %s brief"%(vlan_index),"show interface vlan %s detail"%(vlan_index)]
            checkitemlist = ["vlan %s (.*) %s (.*) up"%(vlan_index,vlan_ip_address),"Interface : vlan %s |  IP address : %s"%(vlan_index,vlan_ip_address),
                             "Interface : vlan %s |  IP address : %s  | Operational : up | MTU : 1500"%(vlan_index,vlan_ip_address)]

            checkitem = "check vlan %s status"%(vlan_index)
            logger.info("[%s]Starting"%(checkitem))
            for index,value in enumerate(checkcommandlist):
                checkmatch = checkitemlist[index]
                device_check_info(logger,device,checkitem,value,checkmatch)

        #check switch vlan and port
        for index, vlan_index in enumerate(vlan_list):
            vlan_ip_mode = vlan_ip_mode_list[index]
            vlan_ip_address = vlan_ip_address_list[index]
            checkcommandlist =["show switch vlan all"]
            checkitemlist = ["VLAN | %s"%(vlan_index)]
            checkitem = "check switch vlan %s status"%(vlan_index)
            logger.info("[%s]Starting"%(checkitem))
            for index,value in enumerate(checkcommandlist):
                checkmatch = checkitemlist[index]
                device_check_info(logger,device,checkitem,value,checkmatch)

            for index, port_vlan in enumerate(port_vlan_index):
                if vlan_index == port_vlan:
                    port_type =port_type_list[index]
                    port_index = port_index_list[index]
                    vlantagged = port_vlan_tagged[index]

                    checkcommandlist =["show switch %s %s"%(port_type,port_index)]
                    checkitemlist = ["%s (.*)  %s"%(vlan_index,vlantagged)]















