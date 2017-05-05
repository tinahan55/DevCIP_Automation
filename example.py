from lib.Device import *
from lib.Configuration import *
from lib.TestRail import *
import os
import sys


logger = Log("example","example")

def set_vlan_port_config():
    configlist = list()

    #set vlan
    vlan_index = 10
    vlan_description = "vlan10"
    ip_mode = "static"
    ipaddress = "192.168.10.1"
    netmask = "255.255.255.0"

    # set port
    port_index = 1
    port_type = "port"
    vlan_tagged = "untagged"
    port_tagged = "untagged"


    # vlan
    function_client1 = Function("vlan")
    configlist.extend(function_client1.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))

    # port
    interface_client1 = Interface("port")
    configlist.extend(interface_client1.get_port_interface(port_index, port_type, vlan_index, vlan_tagged, port_tagged))
    return configlist

def check_result(device_type,testrail_buildversion):
    project_name ="ATS_Test"
    test_plan = "test1"
    test_run = "PreTesting"
    comment = "Auto result upload"
    testrail =TestRailAPI(logname="example")
    checkitem = "client1_config"
    testcaseidlist = [4835,11907]
    checkcommandlist = ["show interface all", "show interface vlan 10 detail"]
    checkitemlist = ["vlan 10" , "IP address : 192.168.10.1"]
    for index, value in enumerate(checkcommandlist):
        test_id = testcaseidlist[index]
        checkmatch = checkitemlist[index]
        title = "[%s][%s]" % (value, checkmatch)
        logger.write("info","%s starting" % (title))
        checkresult = device.device_send_command_match(value, 5, checkmatch)
        logger.write("info","%s check %s result: %s" % (title, checkmatch, checkresult))
        if checkresult == True:
            result = "Passed"
        else:
            result = "Failed"
        updateresult = testrail.update_test_result(project_name,test_plan,test_run,device_type,test_id,testrail_buildversion,result,comment,True)
        logger.write("info","[%s][%s]update_test_result : %s" % (device_type,testrail_buildversion,updateresult))

if __name__ == '__main__':
    if len(sys.argv)>1:
        logger.write("info","Vlan Testing Starting")
        device_info = sys.argv[1].split("_")
        login_info = sys.argv[2].split("_")
        device_connect_type = device_info[0]
        device_ip = device_info[1]
        device_port = int(device_info[2])
        username =login_info[0]
        password =login_info[1]
        interface ="maintenance 0"
        configlist = list()



        ## Device Connection
        device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"example")
        if device:

            ## Get device version for build and typ
            device.device_get_version()
            device.device_get_hostname()
            device.device_get_register_MAC(interface)
            logger.write("info","Device type:%s"%(device.device_type))
            logger.write("info","Device Bios Version:%s"%(device.bios_version))
            logger.write("info","Device recovery image:%s"%(device.boot_image))
            logger.write("info","Device build image:%s"%(device.build_image))
            logger.write("info","Device testrail image:%s"%(device.testrail_build_version))
            logger.write("info","Device mac:%s"%(device.device_register_MAC))
            logger.write("info","Device hostname:%s"%(device.device_hostname))
            logger.write("info","Device version:%s"%(device.branch_version))

            ## get profile list
            device_profile = Device_Profile(device.device_hostname,device.branch_version,device_ip,device.device_register_MAC)
            #device_profile = Device_Profile("Controller2","3.3","10.2.52.53","e4:2c:56:db:fb:a4")

            ## print initial_config
            initial_config = device_profile.get_device_profile_list("Initial Configuration","All")
            for config in initial_config:
                device.device_send_command(config)


            configlist = device_profile.get_config_profile_list("user_testing","All")
            for config in configlist:
                print config
                device.device_send_command(config)

            time.sleep(10)


            checklist = device_profile.get_check_values("checkuser")
            for check in checklist:
                test_id = check["ID"]
                description =  check["Description"]
                command = check["command"]
                checkmatch = check["check"]
                title = "[%s][%s]" % (description, command)
                logger.write("info","%s starting" % (title))
                checkresult = device.device_send_command_match(command, 10, "admin")
                logger.write("info","%s check %s result: %s" % (title, checkmatch, checkresult))
                if checkresult == True:
                    result = "Passed"
                else:
                    result = "Failed"


            #vlan_10_config = device_profile.get_device_profile_list("vlans","vlan10")
            #for config in vlan_10_config:
            #    print config
            #vlan_100_config = device_profile.get_device_profile_list("vlans","vlan100")
            #for config in vlan_100_config:
            #    print config

            #port_value = device_profile.get_device_profile_value("port","appengine")
            #print port_value["default_vlan"],port_value["index"],port_value["port_tagged"],port_value["type"]



            #time.sleep(10)

            #set config
            #device.device_set_configs(vlan_10_config)

            #check result
            #check_result(device.device_type,device.testrail_build_version)

            #logger.write("info","Vlan Testing Done")






























