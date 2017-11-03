__author__ = 'lance'
from lib.powerCycle import *
from lib.Device import *
import sys
import re
import logging
from lib.Tool import *
from time import gmtime, strftime
from lib.TestRail import *

networktool = Network()
mainlogger = Log("Stress_warmboot", "Stress_warmboot")

#OS-1623 for check SSD
#OS-1643 for checking switch interface init


def device_check_info(logger,device,checkitem,checkcommand,checkmatch):
    title = "[%s][%s]"%(checkitem,checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand,5,checkmatch)
    logger.info("%s check %s result :%s"%(title,checkmatch,checkresult))
    if checkresult== False:
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))
        return False
    else:
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

def OS_1623(device):
    device.device_send_command("update terminal paging disable")
    Sata0_result = device.device_send_command(
        "/usr/sbin/udevadm info -q name --name=/dev/disk/by-path/pci-0000:00:13.0-ata-1.0")
    if Sata0_result:
        sub_match = re.findall('sd(.*)\n', device.target_response)
        if sub_match:
            Sata0 = "sd%s" % (sub_match[0])
    checkitem = "check_OS-1623-SSD"
    mainlogger.info("[%s]Starting" % (checkitem))
    checkcommandlist = [ "lsblk -l | grep %s | grep disk" % (Sata0), ]
    checkitemlist = ["%s" % (Sata0_size)]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(mainlogger, device, checkitem, value, checkmatch)

def OS_1643(device):
    checkitem = "Check_OS-1643-switch interface"
    mainlogger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["dmesg | grep eth0"]
    checkitemlist = ["smsc75xx "]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(mainlogger, device, checkitem, value, checkmatch)
    return result

def OS_1807(device):
    checkitem = "Check_OS-1807"
    mainlogger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["show app-engine 0 info","show platform led"]
    checkitemlist = ["Operational : Running","CPU            green"]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result2 = device_check_info(mainlogger, device, checkitem, value, checkmatch)
        if result2 != True:
           print device.target_response
           break

    if result2 == False:
        mainlogger.info("[App-engine_init] test  fail!!")
        return "FAIL"
    else:
        mainlogger.info("[App-engine_init] Successfully!!!")
        return "PASS"
    mainlogger.info("[App-engine_init] is %s..." % (result2))


def OS_1925(device):
    checkitem = "Check_OS-1925"
    mainlogger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["show ipsec connection all", "ping -I 192.168.6.2 -c 5 172.20.6.1"]
    checkitemlist = ["up", "64 bytes from 172.20.6.1: icmp_seq="]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(mainlogger, device, checkitem, value, checkmatch)
        if result == False:
            sqamail = sqa_mail()
            sqamail.send_mail("lance.chien@lileesystems.com", "Taiwan Water Warmboot failed", u"Warmboot result Failed")
    return result

if __name__ == '__main__':
    if len(sys.argv) > 4:
        device_info = sys.argv[1].split("_") #ssh_10.2.66.52_22_admin_admin
        powercycle_info = sys.argv[2].split("_") #200_180

        device_connect_type = device_info[0]
        device_ip = device_info[1]
        device_port = int(device_info[2])
        username = device_info[3]
        password = device_info[4]

        test_cycle = int(powercycle_info[0])
        power_cycle_sleep = int(powercycle_info[1])
    else:
        logfilename = "Stress_warmboot_%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
        #mainlogger = set_log(logfilename,"Stress_warmboot")
        device_ip = "10.2.66.52"
        device_port = 22
        device_connect_type ="ssh"
        username = "admin"
        password ="admin"
        test_cycle = 200
        power_cycle_sleep = 180
        Sata0_size = "29.8G"



    try:
        device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"Stress_warmboot")
        #powerCycle = powerCycle()
        Sata0_size = "29.8G"
        project_name = "LileeOS"
        test_plan = "LileeOS_Weekly_Pretest"
        # test_run = "PreTesting"
        testrail = TestRailAPI(logname="Stress_warmboot")
        comment = "Auto result upload by SQA"

        if device:
            device.device_get_version()
            mainlogger.info("Device Bios Version:%s"%(device.bios_version))
            mainlogger.info("Device recovery image:%s"%(device.boot_image))
            mainlogger.info("Device build image:%s"%(device.build_image))
            device_type = device.device_type
            testrail_buildversion = device.build_image

            for k in range(0, test_cycle):
                #power_cycle_result = powerCycle.powerControl(din_relay_ip, din_relay_user, din_relay_pwd, din_relay_device_name)
                device.device_send_command("show version")
                device.device_send_command("reboot")
                cycle_result = True
                mainlogger.info("[%s][cycle_result]result :%s"%(k,cycle_result))
                if cycle_result:
                    mainlogger.info("[%s][cycle_sleep]%s seconds"%(k,power_cycle_sleep))
                    time.sleep(2)
                    count = check_booting(device_ip,power_cycle_sleep)
                    mainlogger.info("[%s][cycle_sleep]wait %s seconds"%(k,count))
                    if count < power_cycle_sleep:
                        #time.sleep(power_cycle_sleep)
                        device =Device_Tool(device_ip,device_port,device_connect_type,username,password,"Stress_warmboot")
                        if device:
                            OS1807_result = OS_1807(device)
                            if OS1807_result == "FAIL" :
                                updateresult = testrail.update_test_result(project_name, test_plan, "Systems",device_type, 12588, testrail_buildversion,OS1807_result, comment, True)
                                mainlogger.info("[System_Stress_warmboot]update_test_result : %s" % (updateresult))
                                sys.exit(0)
                            time.sleep(20)



    except Exception,ex:
        logging.error("[Stress_warmboot] exception fail:%s "%(str(ex)))
        #sqamail = sqa_mail()
        #sqamail.send_mail("lance.chien@lileesystems.com", "Warmdboot_STS163 Failed", u"Warmboot_STS163 Failed")