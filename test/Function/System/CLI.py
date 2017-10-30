from lib.Device import *
from lib.Configuration import *
from lib.TestRail import *
import os
import sys


logger = Log("CLI_Pretesting","CLI_Pretesting")

if __name__ == '__main__':
        logger.write("info","CLI Testing Starting")
        device_connect_type ="telnet"
        device_ip = '10.2.66.50'
        device_port = 2033
        device_login_username ='admin'
        device_login_password = 'admin'
        device_interface ="eth 0"
        if len(sys.argv) >3:
            device_info = sys.argv[1].split("_")
            login_info = sys.argv[2].split("_")
            device_connect_type = device_info[0]
            device_ip = device_info[1]
            device_port = int(device_info[2])
            device_login_username =login_info[0]
            remote_device_login_password =login_info[1]
            remote_device_interface ="maintenance 0"



        ## Tunnel Server device_ip
        device =Device_Tool(device_ip,device_port,device_connect_type,device_login_username,device_login_password,"example")
        if device.target:
            device.device_send_command("update terminal paging disable",10)
            device.device_get_version()
            device.device_get_hostname()
            device.device_get_register_MAC(device_interface)
            logger.info("Device type:%s"%(device.device_type))
            logger.info("Device Bios Version:%s"%(device.bios_version))
            logger.info("Device recovery image:%s"%(device.boot_image))
            logger.info("Device build image:%s"%(device.build_image))
            logger.info("Device testrail image:%s"%(device.testrail_build_version))
            logger.info("Device mac:%s"%(device.device_register_MAC))
            logger.info("Device hostname:%s"%(device.device_hostname))
            logger.info("Device version:%s"%(device.branch_version))
            logger.info("[%s]CLI testing start now ..." % (device.device_type))

            ##clear configuration
            logger.info("[%s]remote clear the configuration ..." % (device.device_type))
            device.device_no_config()

            print device.device_get_running_config()


            ## set initial configuration
            if device.device_type != 'lmc':
                device.device_send_command("config switch port 0 disable")
                device.device_send_command("config switch port 1 disable")

            ## get profile list
            logger.info("[%s]remote get the configuration ..." % (device.device_type))
            parsingfile = PassProfileJson()
            config_list =  parsingfile.get_config_from_file("CLI_config.json",device.device_type.upper())

            device.device_set_configs(config_list)
            device.device_send_command("save configuration")



            logger.info("[%s] remote wait 20 second ..." % (device.device_type))
            time.sleep(20)

            checkresult = True
            #check running configuration
            logger.info("[%s] check running configuration" % (device.device_type))
            runningconfig = device.device_get_running_config()
            for config in config_list:
                if config not in runningconfig:
                    checkresult =False
                    logger.error("[%s]%s" % (device.device_type,config))

            if checkresult ==  True:
                logger.info("[%s] check running configuration:Pass" % (device.device_type))
            else:
                logger.error("[%s] check running configuration:Fail" % (device.device_type))



            if checkresult ==  True:
                logger.info("[%s] reboot device now ...." % (device.device_type))
                if(device.device_reboot()):
                    device.device_send_command("update terminal paging disable",10)
                    #check startup configuration
                    checkresult = True
                    logger.info("[%s] check startup configuration after rebooting" % (device.device_type))
                    startupconfig = device.device_get_startup_config()
                    for config in config_list:
                        if config not in startupconfig:
                            checkresult =False
                            logger.error("[%s] %s not in startup configuration after rebooting" % (device.device_type,config))
                            logger.error("[%s]startup configuration:%s" % (device.device_type,startupconfig))

            if checkresult ==  True:
                logger.info("[%s] check startup configuration after rebooting:Pass" % (device.device_type))
            else:
                logger.error("[%s] check startup configuration after rebooting:Fail" % (device.device_type))



            if checkresult ==  True:
                runningconfig = device.device_get_running_config()
                for config in config_list:
                    if config not in runningconfig:
                        checkresult =False
                        logger.error("[%s] %s not in running configuration after rebooting" % (device.device_type,config))
                        logger.error("[%s]running configuration:%s" % (device.device_type,runningconfig))


            if checkresult ==  True:
                logger.info("[%s] check running configuration after rebooting:Pass" % (device.device_type))
            else:
                logger.error("[%s] check running configuration after rebooting:Fail" % (device.device_type))


























