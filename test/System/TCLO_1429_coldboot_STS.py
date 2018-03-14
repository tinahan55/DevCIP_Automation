from lib.powerCycle import *
from lib.Device import *
import sys
import re
import logging
from lib.Tool import *
from time import gmtime, strftime
from lib.TestRail import *

networktool = Network()
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
    if checkresult== False or None:
        logger.info("%s check %s error :%s"%(title,checkmatch,device.target_response))
    return checkresult

def check_booting(hostip,check_cycle):
    k = 0
    while k < check_cycle:
        if networktool.Host_Ping(hostip,28):
            break
        else:
            time.sleep(1)
        k+=1
    return k

def OS_2017_ME26(device):
    device.device_send_command("update terminal paging disable")
    Sata0_result = device.device_send_command(
        "dmesg | grep eth0")
    if Sata0_result:
        sub_match = re.findall('added PHC on eth0', device.target_response)
        if sub_match:
            #Sata0 = "sd%s" % (sub_match[0])
            print "Eth0 exist"
        else:
            sys.exit(0)

def OS_1643(device):
    #12039
    checkitem = "Check_OS-1643-switch interface"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["dmesg | grep eth0"]
    checkitemlist = ["smsc75xx"]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result0 = device_check_info(logger, device, checkitem, value, checkmatch)
        if result0 != True:
            print device.target_response
            # print cellular_result
            break

    if result0 == False:
        logger.info("[Switch interface] test  fail!!")
        return "FAIL"
    else:
        logger.info("[Switch interface] Successfully!!!")
        return "PASS"
    logger.info("[switch interface] is %s..." % (result0))

def OS_1623(device):
    #12037,12541(Need to plug one USB for testing)
    device.device_send_command("update terminal paging disable")
    Sata0_result = device.device_send_command(
        "/usr/sbin/udevadm info -q name --name=/dev/disk/by-path/pci-0000:00:13.0-ata-1.0")
    if Sata0_result:
        sub_match = re.findall('sd(.*)\n', device.target_response)
        if sub_match:
            Sata0 = "sd%s" % (sub_match[0])
    checkitem = "check_OS-1623-SSD"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = [ "lsblk -l | grep %s | grep disk" % (Sata0)]
    checkitemlist = ["%s" % (Sata0_size)]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result2 = device_check_info(logger, device, checkitem, value, checkmatch)
        if result2 != True:
            print device.target_response
            # print cellular_result
            break

    if result2 == False:
        logger.info("[SSD_init] test  fail!!")
        return "FAIL"
    else:
        logger.info("[SSD_init] Successfully!!!")
        return "PASS"
    logger.info("[SSD_init] is %s..." % (result2))

def OS_1410(device):
    #12272
    wlan0_mac_address = "04:f0:21:2d:91:00"#"04:f0:21:22:8e:fb"
    wlan1_mac_address = "04:f0:21:2d:90:b6"#"04:f0:21:22:8e:fc"
    checkitem = "Check_OS-1410"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["ifconfig wlan0", "ifconfig wlan1"]
    checkitemlist = ["ether %s" %(wlan0_mac_address), "ether %s" %(wlan1_mac_address)]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result = device_check_info(logger, device, checkitem, value, checkmatch)
        if result!=True:
            print device.target_response
            break

    if result == False:
        logger.info("[WLAN-MAC_info] test  fail!!")
        return "FAIL"
    else:
        logger.info("[WLAN-MAC_info] Successfully!!!")
        return "PASS"
    logger.info("[WLAN-MAC_info] is %s..."% (result))

def Pretesting_Poe(device):

    checkitem = "Pretesting_Poe"
    checkcommandlist = ["show poe budget"]
    if device_type == "sts":
        checkitemlist = ["Oper. Limit: 61.6 watts"]
    elif device_type == "lms":
        checkitemlist = [" Oper.Limit: 132.6 watts"]
    else:
        logger.info("Device Type is %s" % (device_type))

    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result3 = device_check_info(logger, device, checkitem, value, checkmatch)
        if result3 == False:
            logger.info("[Pretesting_Poe] Test  fail!!")
            return "FAIL"
        else:
            logger.info("[Pretesting_Poe] Successfully!!!")
            return "PASS"
        logger.info("[Pretesting_Poe] is %s..." % (result3))

def OS_1932(device):
    checkitem = "Check_OS-1923"
    logger.info("[%s]Starting" % (checkitem))
    checkcommandlist = ["ping 192.168.99.253 -c 5","show sim-management current-status"]
    checkitemlist = ["64 bytes from 192.168.99.253: icmp_seq=","dialer 0"]
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result0 = device_check_info(logger, device, checkitem, value, checkmatch)
        print device.target_response
        if result0 != True:
            # print cellular_result
            break

    if result0 == False:
        logger.info("[Switch interface] test  fail!!")
        return "FAIL"
    else:
        logger.info("[Switch interface] Successfully!!!")
        return "PASS"
    logger.info("[switch interface] is %s..." % (result0))

def OS_1932_dd(device,limit):
    dd_limit=limit
    checkitem = "Check_OS-1923_dd"
    logger.info("[%s]Starting" % (checkitem))
    device.device_send_command("rm /data/sqa*")
    if dd_limit < 40:
        dd_cli = ("dd if=/dev/urandom of=/data/sqa%d.img bs=512k count=2048") % (dd_limit)
        logger.info("[App-Engine_DD] Start!")
        device.device_send_command(dd_cli)
        time.sleep(25)
        #device.device_send_command("ls /data | grep sqa*")
        print device.target_response
        dd_limit += 1
        #device.device_send_command("exit")
        device.device_send_command_match("exit", 5, "sts@sts-appengine(.*)")
        device.device_send_command("exit")
        return True
    else:
        dd_limit = 0
        dd_cli = ("dd if=/dev/urandom of=/data/sqa%d.img bs=512k count=2048") % (dd_limit)
        logger.info("[App-Engine_DD_%d] Start!")
        device.device_send_command(dd_cli)
        time.sleep(25)
        #device.device_send_command("ls /data | grep sqa*")
        print device.target_response
        dd_limit += 1
    #return "PASS"

def OS_1932_root(device):
    root_cli="Lilee1234"
    device.device_send_command("date")
    device.device_send_command("sudo -s")
    result0 = device.device_send_command_match(root_cli,5,"root@sts-appengine(.*)")
    print device.target_response
    if result0:
        logger.info("[App-Engine_root] Success")
        return result0
    else:
        device.device_send_command("^c")
        return result0

def TCLO_1429(device):
    dd_cli = ("time fsck -c -C0 -v -f /dev/sda1")
    logger.info("[System Fsck] Start!")
    device.device_send_command(dd_cli,60)
    logger.info(device.target_response)
    if "bash-4.2#" not in device.target_response:
        print device.target_response
        return False


if __name__ == '__main__':
    logfilename = "TCLO1429%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"TCLO1429")
    ip = "10.2.8.251"#"10.2.8.252"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"

    # Power Server
    din_relay_ip = "10.2.11.49"#'10.2.66.56'
    din_relay_user ="admin"
    din_relay_pwd ="lilee1234"
    din_relay_index = 8
    din_relay_cmd ="CCL"

    #condition_info
    cycle_times = 500

    power_cycle_sleep = 120
    Sata0_size = "29.8G"
    project_name = "LileeOS"
    test_plan = "LileeOS_Weekly_Pretest"
    #test_run = "PreTesting"
    testrail = TestRailAPI(logname="TCLO1429")
    comment = "Auto result upload by SQA"

    if len(sys.argv)>3:
        device_info =sys.argv[1].split("_") #ssh_10.2.66.52_22_admin_admin
        #lmc_info = sys.argv[2].split("_") #ssh_10.2.53.203_22_admin_Lilee1234
        din_server_info = sys.argv[2].split("_")#10.2.66.56_admin_lilee1234_5_CCL
        #command_info = sys.argv[4].split("_") #R11-STS2_3.4_GET_statistic/report_5_10
        condition_info =sys.argv[3].split("_")#200

        # device_info
        device_connect_mode = device_info[0]
        device_ip = device_info[1]
        device_port = device_info[2]
        device_username = device_info[3]
        device_password = device_info[4]

        # Power Server
        din_relay_ip = din_server_info[0]
        din_relay_user =din_server_info[1]
        din_relay_pwd =din_server_info[2]
        din_relay_index = din_server_info[3]
        din_relay_cmd =din_server_info[4]

        #condition_info
        cycle_times = int(condition_info[0])

    try:
        device =Device_Tool(ip,port,mode,username,password,"TCLO1429")
        powerCycle = powerCycle()
        pass_count = 0

        if device:
            device.device_get_version()
            logger.info("Device Bios Version:%s"%(device.bios_version))
            logger.info("Device recovery image:%s"%(device.boot_image))
            logger.info("Device build image:%s"%(device.build_image))
            testrail_buildversion = device.build_image
            device_type = device.device_type


            for k in range(0, cycle_times):
                power_cycle_result = powerCycle.powercontrolbyIndex(din_relay_ip, din_relay_user, din_relay_pwd,din_relay_index, din_relay_cmd)
                logger.info("[%s][power_cycle_result]result :%s" % (k+1, power_cycle_result))
                if power_cycle_result:
                    logger.info("[%s][power_cycle_sleep]%s seconds"%(k+1,power_cycle_sleep))
                    time.sleep(2)
                    count = check_booting(ip,power_cycle_sleep)
                    logger.info("[%s][power_cycle_sleep]wait %s seconds"%(k+1,count))
                    if count < power_cycle_sleep:
                        #time.sleep(power_cycle_sleep)
                        device =Device_Tool(ip,port,mode,username,password,"TCLO1429")
                        if device:
                            print k
                            if (k+10)%10==0:
                                logger.info("[sleep]wait 900 seconds")
                                time.sleep(900)
                            else:
                                logger.info("[sleep]wait 100 seconds")
                                time.sleep(100)
                            ''''dnat_device = Device_Tool(ip, 2222, "ssh", "sts", "Lilee1234", "OS1932")
                            if dnat_device:
                                while True:
                                    if OS_1932_root(dnat_device):
                                        break;
                                OS_1932_dd(dnat_device,k)'''
                            result = TCLO_1429(device)
                            if result == False:
                                sqamail = sqa_mail()
                                sqamail.send_mail("lance.chien@lileesystems.com", "R4-STS  STOP", u"TCLO-1429"u" Failed")
                                sys.exit(0)

    except Exception,ex:
        logging.error("[coolboot]exception fail:%s "%(str(ex)))


