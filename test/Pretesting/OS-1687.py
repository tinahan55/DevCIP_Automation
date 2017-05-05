__author__ = 'lance'
from lib.powerCycle import *
from lib.Device import *
import sys
import re
import logging
from lib.Tool import *
from time import gmtime, strftime

networktool = Network()
mainlogger = Log("OS-1687", "OS-1687")



def device_check_info(logger,device,checkitem,checkcommand,checkmatch):
    title = "[%s][%s]"%(checkitem,checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand,5,checkmatch)
    logger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
    if checkresult== False:
        return checkresult
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))
    return checkresult

def  check_booting(hostip,check_cycle):
    k = 0
    while k < check_cycle:
        if networktool.Host_Ping(hostip,30):
            break
        else:
            time.sleep(1)
        k+=1
    return k

if __name__ == '__main__':
    if len(sys.argv) > 4:
        device_info = sys.argv[1].split("_")
        login_info = sys.argv[2].split("_")
        din_relay_info = sys.argv[3].split("_")
        powercycle_info = sys.argv[4].split("_")
        device_connect_type = device_info[0]
        device_ip = device_info[1]
        device_port = int(device_info[2])
        username = login_info[0]
        password = login_info[1]
        din_relay_ip = din_relay_info[0]
        din_relay_user = din_relay_info[1]
        din_relay_pwd = din_relay_info[2]
        din_relay_device_name = din_relay_info[3]
        test_cycle = int(powercycle_info[0])
        power_cycle_sleep = int(powercycle_info[1])
        print sys.argv
    else:
        logfilename = "OS-1687%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
        #mainlogger = set_log(logfilename,"OS-1623_ssd")
        device_ip = "10.2.53.159"
        device_port = 22
        device_connect_type ="ssh"
        username = "admin"
        password ="admin"
        din_relay_ip = "10.2.53.199"
        din_relay_user ="root"
        din_relay_pwd ="lilee1234"
        din_relay_device_name = "R1-159"
        #"R1-158"
        test_cycle = 2000
        power_cycle_sleep = 180
        Sata0_size = "29.8G"

    try:
        device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"OS-1687")
        powerCycle = powerCycle()

        if device:
            device.device_get_version()
            mainlogger.info("Device Bios Version:%s"%(device.bios_version))
            mainlogger.info("Device recovery image:%s"%(device.boot_image))
            mainlogger.info("Device build image:%s"%(device.build_image))

            for k in range(0, test_cycle):

                #mainlogger.info("[%s][power_cycle_result]result :%s" % (k, power_cycle_result))
                power_cycle_result = powerCycle.powerControl(din_relay_ip, din_relay_user, din_relay_pwd, din_relay_device_name)
                mainlogger.info("[%s][power_cycle_result]result :%s"%(k,power_cycle_result))
                if power_cycle_result:
                    mainlogger.info("[%s][power_cycle_sleep]%s seconds"%(k,power_cycle_sleep))
                    time.sleep(2)
                    count = check_booting(device_ip,power_cycle_sleep)
                    mainlogger.info("[%s][power_cycle_sleep]wait %s seconds"%(k,count))
                    if count < power_cycle_sleep:
                        #time.sleep(power_cycle_sleep)
                        device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"OS-1687")
                        if device:
                            device.device_send_command("update terminal paging disable")
                            device.device_send_command("show platform led")
                            device.device_send_command("ifconfig -a")
                            dialer0_result = device_check_info(mainlogger, device, "OS-1687-D0","show interface all","dialer 0(.*) up")
                            if dialer0_result == False:
                                device.device_send_command("dmesg | grep usb1")
                                device.device_send_command("show running-configuration")
                                device.device_send_command("show startup-configuration")
                                break
                            dialer1_result = device_check_info(mainlogger, device, "OS-1687-D1","show interface all","dialer 1(.*) up")
                            if dialer1_result == False:
                                device.device_send_command("dmesg | grep usb2")
                                device.device_send_command("show running-configuration")
                                device.device_send_command("show startup-configuration")
                                break
                            wlan0_result = device_check_info(mainlogger, device, "OS-1687-W0","show interface all","wlan 0(.*) up")
                            if wlan0_result == False:
                                device.device_send_command("dmesg | grep wlan0")
                                device.device_send_command("show running-configuration")
                                device.device_send_command("show startup-configuration")
                                break
                            '''
                                                        wlan1_result = device_check_info(mainlogger, device, "OS-1687-W1","show interface all","wlan 1(.*) up")
                                                        if wlan1_result == False:
                                                            device.device_send_command("dmesg | grep wlan1")
                                                            device.device_send_command("show running-configuration")
                                                            device.device_send_command("show startup-configuration")
                                                            break
                                                        '''
    except Exception,ex:
        logging.error("[OS-1687]exception fail:%s "%(str(ex)))