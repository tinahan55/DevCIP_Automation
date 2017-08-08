__author__ = 'Lance'
from lib.Device import *
from lib.Configuration import *
import os
from time import gmtime, strftime
from lib.SSHConsole import *

logger = Log("dialer_pretest","dialer_pretest")
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

def get_dialer_port(): # For interface dialer
    #port_array = "2/2"
    if  "LMS" in Server_Type:
        port= "0"
    elif "DTS" in Server_Type:
        port="0"
    elif "STS" in Server_Type:
         port="0"
    return port

def get_cellular_port(): # For cellular index
    #port_array = "2/2"
    if  "LMS" in Server_Type:
        index= "0/1"
    elif "DTS" in Server_Type:
        index="0/1"
    elif "STS" in Server_Type:
         index="0"
    return index

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

def Dialer_system_check(device):
    logger.info("[DUT] Cellular pretest ")
    logger.info("[Dialer_CPIN_Check] Testing ...")
    server_command = "debug line cellular %s cpin" % (cellular_index)
    server_command_match = "CPIN: READY"
    matchresult0 = device.device_send_command_match(server_command, 10, server_command_match)
    if matchresult0==False:
        pretest_result=matchresult0
    else:
        logger.info("[Dialer_CPIN_Check Successfully")
        logger.info("[Dialer_SlotMappingCheck] Testing ...")
        server_command1 = "slotmapping -l"
        if "STS" in Server_Type:
            matchresult1 = device.device_send_command_match(server_command1, 10, "0: /sys/devices/pci0000:00/0000:00:1c.1/0000:02:00.0/usb4/4-1&&(.*)PRODUCT  Sierra Wireless(.*)&&(.*)MODEM(.*)ttyUSB2")
        else:
            matchresult1 = device.device_send_command_match(server_command1, 10,"PRODUCT  MC73(.*)&&(.*)MODEM    ttyUSB(.*)&&(.*)USBNET   usb(.*)")
        if matchresult1==False:
            pretest_result = matchresult1
            logger.info("[Dialer_SlotMappingCheck] Failed")
        else:
            logger.info("[Dialer_SlotMappingCheck] Successfully")
            logger.info("[Dialer_ModemCheck] Testing start...")
            server_command2 = " debug line cellular %s atcmd \"at!gstatus?\"" % (cellular_index)
            server_command_match2 = "Mode:        ONLINE"
            matchresult2 = device.device_send_command_match(server_command2, 10, server_command_match2)
            if matchresult2==False:
                pretest_result = matchresult2
                logger.info("[Dialer_ModemCheck] failed...")
            else:
                logger.info("[Dialer_ModemCheck] Successfully")
                pretest_result = matchresult2
    logger.info("[DUT] Cellular pretest is %s"%(pretest_result))
    return pretest_result

def Dialer_Get_Firmware_index(device):
    logger.info("[Dialer_Get_Firmware-list] Testing start...")
    command0 = "show line cellular all"
    result0 = device.device_send_command_match(command0, 10, "Unknown")
    if result0:
        sub_match0 = re.findall(r'cellular\s*%s\s*([A-Za-z]+)\s*' % (cellular_index), device.target_response)
        # print sub_match0
        run_version = sub_match0[0].upper()
        #print run_version

    command1 = "show line cellular %s firmware-list" % (cellular_index)
    result1 = device.device_send_command_match(command1, 10, "localdomain ")
    if result1:
        sub_match1 = re.findall(r'(\d)(.*)_%s' % (run_version), device.target_response)
        #print device.target_response
        #print sub_match1[0][0]
        index_active = sub_match1[0][0]

        '''sub_match2 = re.findall(r"(\d+.\d+.\d+.\d+\d+_\S+)", device.target_response)
        index_num = sub_match2.__len__() / 2'''
        return index_active, run_version

def Dialer_firmware_switch(device): #STS support only
    logger.info("[firmware_switch] Testing...")
    if "STS" in Server_Type:
        command0 = "show line cellular %s firmware-list" % (cellular_index)
        result0 = device.device_send_command_match(command0, 10, "localdomain ")
        if result0:
            logger.info("[Max Firmware index] Get max-index")
            sub_match0 = re.findall(r"(\d+.\d+.\d+.\d+\d+_\S+)", device.target_response)
            max_index = sub_match0.__len__() / 2
            count=1
            update_result=result0
            while count < (max_index+1):
                logger.info("[Dialer_Update_firmware-%d_%d]  Testing start..." % ( max_index, count))
                command1 = "update line cellular %s firmware-switch %s " % (cellular_index, count)
                result = device.device_send_command_match(command1, 300,"Please wait 2 mins ")
                #print device.target_response
                #count= count + 1
                if result==False:
                    logger.info("[Firmware_switch] index %s switch failed..." % (count))
                    print "Update failed"
                    update_result=result
                    break
                else:
                    logger.info("[Update_firmware-%d_%d] Successfully" % (max_index, count))
                    command2 = "show line cellular %s firmware-list" % (cellular_index)
                    result2 = device.device_send_command_match(command2, 10, "localdomain ")
                    if result2:
                        logger.info("[Check_firmware_%d_%d]  Testing start..." % (max_index, count))
                        sub_match2 = re.findall(r"((\d)(.*)_(.*) V)", device.target_response)
                        if count.__str__() == (sub_match2[0][0][0]):
                            print "Check_True"
                            result2 = Dialer_Custom_Check(device)
                            update_result = result2
                            logger.info("[Check_firmware_%d_%d]  Check correct..." % (max_index, count))
                        else:
                            print "Check_False"
                            logger.info("[Check_firmware_%d_%d]  Check failed..." % (max_index, count))
                            update_result = result2
                count = count + 1
        else:
            logger.info("[Max Firmware index] Get max-index failed")
            update_result = result0
        logger.info("[Change_firmware to Generic] ")
        device.device_send_command("update line cellular %s firmware-switch 3 " % (cellular_index))
        time.sleep(160)
        return update_result

def Dialer_Update_firmware(device): #Suggest to execute locally, because need to reboot DUT after update each firmware
    Update_result = False
    command_route= "config route ip network 10.1.0.0 netmask 255.255.0.0 interface maintenance 0"
    result = device.device_send_command_match(command_route, 10, "localdomain")
    if result==False:
        logger.info("[Update Firmware] Add route failed...")
        Update_result = result
    else:
        command0 = "show line cellular %s hardware" % (cellular_index)
        result0 = device.device_send_command_match(command0, 10, "IMEI")
        #Update_result = result0
        if result0==False:
            logger.info("[Update Firmware] Get Cellular info failed...")
            Update_result = result0
            #return Update_result
        else:
            sub_match0 = re.findall(r'Model: MC(\d*)', device.target_response)
            type = sub_match0[0]
            #print type
            time.sleep(15)
            device.device_send_command("ping -c3 10.1.10.11")
            if "7304" in type:
                checkcommandlist = [firm_VODA_7304,firm_Telstra_7304,firm_Generic_7304]
                checkitemlist = ["Vodafone","Telstra","Generic"]
                sleep_wirte= 160
                sleep_wait= 120
            elif "7354" in type:
                checkcommandlist = [firm_ATT_7354, firm_VZW_7354, firm_SPRINT_7354,firm_BELL_7354,firm_TELUS_7354,frim_ROGERS_7354,firm_GENNA_7354]
                checkitemlist = ["AT&T","Verizon","Sprint","Bell", "Telus","Rogers", "Generic"]
                sleep_wirte= 160
                sleep_wait= 120
            elif "7455" in type:
                checkcommandlist = [firm_VZW_7455,firm_ATT_7455,firm_GENERIC_7455, firm_SPRINT_7455,firm_VODA_7455,frim_ROGERS_7455]
                checkitemlist = ["Verizon","AT&T", "Generic","Sprint","Vodafone","Rogers"]
                sleep_wirte = 320
                sleep_wait = 200
            elif "7430" in type:
                checkcommandlist = [firm_DoCoMo_7430, firm_Telstra_7430,firm_KDDI_7430,firm_SoftBank_7430,firm_Generic_7430]
                checkitemlist = ["NTT docomo", "Telstra","KDDI", "Softbank", "Generic"]
                sleep_wirte = 250
                sleep_wait = 200

            logger.info("[Update Firmware] %s Start..." % (type))
            for index, value in enumerate(checkcommandlist):
                #logger.info("[Update Firmware] %s Start..." % (type))
                checkmatch = checkitemlist[index]
                command0 = "update line cellular %s image %s" % (cellular_index, value)
                logger.info("[Update Firmware] %s %s Testing %s seconds ..." % (type,checkmatch,sleep_wirte))
                result0 = device.device_send_command_match(command0, sleep_wirte, "Download firmware 100%") #LMS160
                #print device.target_response
                if result0==False:
                    logger.info("[Update Firmware] %s %s Failed..." % (type, checkmatch))
                    print device.target_response
                    Update_result = result0
                    print Update_result
                    break
                else:
                    logger.info("[Update Firmware] Sleep %s seconds..." % (sleep_wait))
                    time.sleep(sleep_wait) #LMS120
                    #print sleep_wait
                    command1 = "show line cellular %s detail" % (cellular_index)
                    result1 = device.device_send_command_match(command1, 10, "RSRQ :")
                    #print device.target_response
                    if result1==False:
                        logger.info("[Update Firmware] Show %s %s cellular info Failed..." % (type, checkmatch))
                        Update_result = result1
                        #print Update_result
                    else:
                        logger.info("[Update Firmware] Check %s %s cellular info ..." % (type, checkmatch))
                        sub_match1 = re.findall(r'Firmware : (.*)', device.target_response)
                        print sub_match1[0]
                        if sub_match1[0] != checkmatch:
                            logger.info("[Update Firmware] %s %s cellular info Mismatch..." % (type, checkmatch))
                            Update_result = False
                            #print Update_result
                            break
                        else:
                            logger.info("[Update Firmware] %s %s cellular info Successfully..." % (type, checkmatch))
                            Update_result = True
                            print device.target_response
    return Update_result

def Dialer_Custom_Check(device):
    logger.info("[Dialer_Custom Check] Testing start...")
    custom_result= True
    command0 = "show line cellular all"
    result0 = device.device_send_command_match(command0, 10, "Unknown")
    if result0:
        sub_match0 = re.findall(r'cellular\s*%s\s*([A-Za-z]+)\s*' % (cellular_index), device.target_response)
        # print sub_match0
        type = sub_match0[0].upper()
        #print type
        if type =="GENERIC":
            logger.info("[Dialer_Custom Check] %s Testing start..."%(type))
            command = "debug line cellular %s atcmd \"at!custom?\"" % (cellular_index)
            custom_result=device.device_send_command_match(command,20,"GPSENABLE(.*)0x01&&(.*)GPSLPM(.*)0x01&&(.*)IPV6ENABLE	(.*)0x01&&(.*)UIM2ENABLE	(.*)0x01&&(.*)SIMLPM(.*)0x01&&(.*)USBSERIALENABLE(.*)0x01&&(.*)SINGLEAPNSWITCH(.*)0x01")
            logger.info("[Custom Check] %s" % (device.target_response))
            print device.target_response

        elif type =="SPRINT":
            logger.info("[Dialer_Custom Check] %s Testing start..." % (type))
            command = "debug line cellular %s atcmd \"at!custom?\"" % (cellular_index)
            custom_result = device.device_send_command_match(command, 20,"GPSENABLE(.*)0x01&&(.*)GPSLPM(.*)0x01&&(.*)IPV6ENABLE	(.*)0x01&&(.*)UIM2ENABLE	(.*)0x01&&(.*)SIMLPM(.*)0x01&&(.*)USBSERIALENABLE(.*)0x01")
            logger.info("[Custom Check] %s" % (device.target_response))

        elif type =="AT":
            logger.info("[Dialer_Custom Check] %s Testing start..." % (type))
            command = "debug line cellular %s atcmd \"at!custom?\"" % (cellular_index)
            custom_result = device.device_send_command_match(command, 20,"GPSENABLE(.*)0x01&&(.*)GPSLPM(.*)0x01&&(.*)IPV6ENABLE	(.*)0x01&&(.*)CFUNPERSISTEN(.*)0x01(.*)&&(.*)UIM2ENABLE	(.*)0x01&&(.*)SIMLPM(.*)0x01&&(.*)USBSERIALENABLE(.*)0x01&&(.*)PCSCDISABLE(.*)0x03(.*)&&(.*)SINGLEAPNSWITCH(.*)0x01")
            logger.info("[Custom Check] %s" % (device.target_response))

        elif type =="VERIZON":
            logger.info("[Dialer_Custom Check] %s Testing start..." % (type))
            command = "debug line cellular %s atcmd \"at!custom?\"" % (cellular_index)
            custom_result = device.device_send_command_match(command, 20,"GPSENABLE(.*)0x01&&(.*)GPSLPM(.*)0x01&&(.*)IPV6ENABLE	(.*)0x01&&(.*)UIM2ENABLE	(.*)0x01&&(.*)SIMLPM(.*)0x01&&(.*)USBSERIALENABLE(.*)0x01")
            logger.info("[Custom Check] %s" % (device.target_response))

    return custom_result

def Server_set_dialer(device):
    configlist = list()
    # profile and dialer
    profile_name = "LTE"
    access_name = "internet"
    #dialer_index = 0
    #cellular_index = "0/1"
    #if 'STS' in Server_Type: cellular_index = "1"
    result = False
    logger.info("[DUT] Enable interface dialer")
    profile = Profile("Profile")
    configlist.extend(profile.get_cellular_profile(profile_name, access_name))
    interface_dialer = Interface("server_dialer")
    configlist.extend(interface_dialer.get_dialer_interface(dialer_index, profile_name, cellular_index))

    device.device_set_configs(configlist)

    time.sleep(20)
    checkitem = "server_set_dialer"
    checkcommandlist = [ "show interface dialer %s detail" % (dialer_index)]
    checkitemlist = ["Operational : up"]
    logger.info("[%s]Starting" % (checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        result =device_check_info(logger, device, checkitem, value, checkmatch)
        time.sleep(10)
        if result == False:
            #print device.target_response
            return result
    logger.info("[DUT] Enable interface dialer is %s"%(result))
    return result

def Dialer_Simlot_Change(device):
    sim_result=True
    logger.info("[Check Sim-slot]")
    device.device_send_command("config line cellular %s sim-card-slot 0" % (cellular_index))
    time.sleep(160)
    '''if "STS" in Server_Type:
        command0 ='debug line cellular %s atcmd "at!uims?"' % (cellular_index)
        command0_match = "!UIMS: 0"
        result0 = device.device_send_command_match(command0, 5, command0_match)
        #print result0
        if result0 == False:
            logger.info("[Simlot_Change to slot 0]")  # Force sim-slot to 0
            device.device_send_command("config line cellular %s sim-card-slot 0" % (cellular_index))
            time.sleep(160)
            sim_result = Dialer_Simlot_Change(device)
        else:
            logger.info("[Simlot_Change] Setting  start")
            command = "config line cellular %s  sim-card-slot 1" % (cellular_index)
            command_match = "localdomain"
            result = device.device_send_command_match(command, 10, command_match)
            time.sleep(160)
            if result == False:
                logger.info("[Config_Simlot_Change] Failed")
                sim_result = result
    else:
        command0 = 'show cellular-profile LTE'
        command0_match = "Sim card slot : 0"
        result0 = device.device_send_command_match(command0, 5, command0_match)
        if result0==False:
            logger.info("[Simlot_Reset to slot 0]") #Force sim-slot to 0
            device.device_send_command("config line cellular 0/1  sim-card-slot 0")
            time.sleep(60)
            sim_result=Dialer_Simlot_Change(device)
        else:
            logger.info("[Simlot_Change] Setting  start")
            command = "config line cellular 0/1  sim-card-slot 1"
            command_match = "localdomain"
            result = device.device_send_command_match(command, 10, command_match)
            time.sleep(60)
            if result == False:
                logger.info("[Config_Simlot_Change] Failed")
                sim_result = result'''
    logger.info("[Simlot_Change] Setting  start")
    command = "config line cellular %s  sim-card-slot 1" % (cellular_index)
    command_match = "localdomain"
    result = device.device_send_command_match(command, 10, command_match)
    time.sleep(120)
    sim_result = result
    if result == False:
        logger.info("[Config_Simlot_Change] Failed")


    if sim_result:
        if "STS" in Server_Type:
            Iccid00 = "89886920041308836573"
            Iccid01 = "89886891000087039135"
        else:
            Iccid00 = "89886891000087039127"
            Iccid01 = "89886920031026180016"

        logger.info("[Simlot_Change] Checking start...")
        command1='show running-configuration'
        result1= device.device_send_command_match(command1.strip(), 30,"config sim-management iccid %s line cellular %s sim-card-slot 1"%(Iccid01,cellular_index))
        if result1==False:
            logger.info("[Sim_Iccid] Failed...")
            sim_result = result1
        else:
            command2= 'show sim-management current-status'
            #command2_match ="%s&& dialer %s" %(Iccid01,cellular_index)
            result2 = server_device.device_send_command_match(command2, 10,"%s   dialer 0(.*)%s(.*)1" % (Iccid01, cellular_index))
            print result2
            if result2==False:
                logger.info("[Check_Sim_Iccid] Failed...")
            else:
                sub_match3 = re.findall(r"%s\s+dialer\s(\d)"%(Iccid01), device.target_response)
                if sub_match3[0]==dialer_index:
                    logger.info("[Simlot_Change] Testing Successfully on sim-slot-0")
                    sim_result = result2
                    server_command = "ping -c5 -I usb%s %s"% (int(dialer_index)+1,public_ping_ip)
                    server_command_match = "64 bytes from %s: icmp_seq=5" % (public_ping_ip)
                    matchresult = device.device_send_command_match(server_command, 20, server_command_match)
                    if matchresult == True:
                        logger.info("[Simlot_Change] Ping Testing Successfully on sim-slot-0")
                        sim_result = matchresult
                    else:
                        logger.info("[Simlot_Change] Ping Testing failed on sim-slot-0")
                        sim_result = matchresult
    device.device_send_command("config line cellular %s sim-card-slot 0" % (cellular_index))
    time.sleep(160)
    return sim_result

def Dialer_Iccid_info(device):
    logger.info("[Dialer_Iccid-info] Testing start...")
    server_command = "show sim-management current-status"
    server_command_match = "%s" % (Iccid00)
    result0 = device.device_send_command_match(server_command, 20, server_command_match)
    # matchresult = server_device.device_send_command_match(server_command, 20, server_command_match)
    if result0 == False:
        logger.info("[Dialer_Iccid-info] test  fail!!")
    else:
        logger.info("[Dialer_Iccid-info] Successfully!!!")
    logger.info("[Dialer_Iccid-info] is %s..."% (result0))
    return result0

def Dialer_RRC_Check(device):
    device.device_send_command("ping -c 5 -I usb%d 8.8.8.8"%(int(dialer_index)+1))
    RRC_command = " dialer_info -z %s " % (cellular_index)
    RRC_command_match= "RRC State: RRC Connected"
    logger.info("[Dialer_RRC_Check] Testing start...")
    matchresult = device.device_send_command_match(RRC_command , 10,RRC_command_match)
    if (matchresult == False):
        logger.info("[Dialer_RRC_Check] test  fail!!")
    else:
        logger.info("[Dialer_RRC_Check] Successfully!!!")
    logger.info("[DUT] Check dialer RRC state is %s"%(matchresult))
    return matchresult

def Dialer_ODIS_Check(device): #STS support only for AT&T testing, no need to put into regression test
    Manufacturer_id="LileeSQA"
    Plasma_id="PlasmaID01"
    ODIS_show="show line cellular %s odis-information" % (cellular_index)
    ODIS_command= 'update line cellular %s odis-set "%s" "%s" "%s" "%s"' % (cellular_index,Manufacturer_id,server_device.device_type,3.4,Plasma_id)
    ODIS_command_match="Done"
    ODIS_command_match1="Manufacturer:LileeSQA&&Model:sts&&Software Version:3.4&&Plasma ID:PlasmaID01" #%(server_device.build_image)
    logger.info("[Dialer_ODIS_setting] Testing start...")
    matchresult = device.device_send_command_match(ODIS_command, 10, ODIS_command_match)
    matchresult1 = device.device_send_command_match(ODIS_show, 10, ODIS_command_match1)
    #print device.target_response
    if (matchresult1 == False):
        logger.info("[Dialer_ODIS_setting] test  fail!!")
    else:
        logger.info("[Dialer_ODIS_setting] Successfully!!!")
    return matchresult


#main( connect -> initial setup -> catch config -> compare -> append config -> show and verify)
if __name__ == '__main__':
    connecttype = "ssh"
    set_result = True

    #STS
    #Server_Type = "LMS"
    server_ip = "10.2.66.65" # STS ip 10.2.66.65, LMS ip 10.2.66.64
    server_port = 22
    server_maintenance_ip = "10.2.66.65"
    server_login_user ="admin"
    server_login_password ="admin"


    public_ping_ip= "8.8.8.8"
    #LTE lastes firmware path: http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/     0612 edited
    # MC7304 LTE firmware
    firm_Generic_7304= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7304/9999999_9902674_SWI9X15C_05.05.58.00_00_GENEU-4G_005.026_000-field.spk"
    firm_Telstra_7304= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7304/9999999_9902509_SWI9X15C_05.05.58.00_00_TELSTRA_005.021_000-field.spk"
    firm_VODA_7304= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7304/9999999_9903271_SWI9X15C_05.05.61.00_00_VODA-EU_005.024_000-field.spk"
    #server_path = 'http://10.2.10.189/Tmp_Files/LTE/'
    # MC7354 LTE firmware
    firm_ATT_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902196_SWI9X15C_05.05.58.00_00_ATT_005.026_000-field.spk"
    firm_VZW_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902266_SWI9X15C_05.05.58.01_00_VZW_005.029_000-field.spk"
    firm_SPRINT_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902350_SWI9X15C_05.05.63.01_00_SPRINT_005.035_000-field.spk"
    firm_GENNA_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902574_SWI9X15C_05.05.58.00_00_GENNA-UMTS_005.025_002-field.spk"
    firm_BELL_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902844_SWI9X15C_05.05.58.00_00_BELL_005.023_000-field.spk"
    firm_TELUS_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902845_SWI9X15C_05.05.58.00_00_TELUS_005.023_000-field.spk"
    frim_ROGERS_7354= "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7354/9999999_9902907_SWI9X15C_05.05.58.00_00_ROGERS_005.022_000-field.spk"
    # MC7455 LTE firmware
    firm_ATT_7455 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7455/SWI9X30C_02.20.03.00_ATT_002.020_000.zip"
    firm_VZW_7455 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7455/SWI9X30C_02.20.03.22_Verizon_002.026_001.zip"
    firm_SPRINT_7455 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7455/SWI9X30C_02.20.03.22_Sprint_002.020_000.zip"
    firm_GENERIC_7455 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7455/SWI9X30C_02.20.03.00_GENERIC_002.017_001.zip"
    firm_VODA_7455 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7455/SWI9X30C_02.14.03.00_Vodafone_000.008_000.zip"
    frim_ROGERS_7455 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7455/SWI9X30C_02.08.02.00_Rogers_000.001_002.zip"
    # MC7430 LTE firmware
    firm_DoCoMo_7430 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7430/SWI9X30C_02.20.03.00_DoCoMo_001.001_000.zip"
    firm_Generic_7430 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7430/SWI9X30C_02.24.03.00_GENERIC_002.021_000.zip"
    firm_Telstra_7430 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7430/SWI9X30C_02.20.03.01_Telstra_002.019_001.zip"
    firm_KDDI_7430 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7430/SWI9X30C_02.20.03.00_KDDI_000.008_000.zip"
    firm_SoftBank_7430 = "http://10.1.10.11/tftpboot/RELEASE/SierraWireless/latest/MC7430/SWI9X30C_02.20.03.00_Softbank_000.007_000.zip"

    if len(sys.argv) >1:
        connect_type = sys.argv[1]
        Server_Info = sys.argv[2] #telnet_10.2.66.50_2040_10.2.66.61_admin_admin =>connecttype_ip_port_maintenceip_username_password
        server_connect_type = Server_Info.split("_")[0]
        server_ip =Server_Info.split("_")[1]
        server_port =Server_Info.split("_")[2]
        server_maintenance_ip = Server_Info.split("_")[3]
        server_login_user = Server_Info.split("_")[4]
        server_login_password = Server_Info.split("_")[5]

    #DUT set configuration
    logger.info("Dialer Pretesting")
    server_device = Device_Tool(server_ip, server_port, connecttype, server_login_user, server_login_password, "dialer_pretest")
    if server_device.target:

        server_device.device_send_command("update terminal paging disable",5)
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
        server_device.device_send_command("config switch port 0 disable")


    if server_device:
        dialer_index = get_dialer_port()
        cellular_index = get_cellular_port()

        if "STS" in Server_Type:
            Iccid00 = "89886920041308836573"
            Iccid01 = "89886891000087039135"
        else:
            Iccid00 = "89886891000087039127"
            Iccid01 = "89886920031026180016"

        set_result = Dialer_system_check(server_device)
        if set_result:set_result = Dialer_Iccid_info(server_device)
        if set_result:set_result = Server_set_dialer(server_device)
        logger.info("[DUT]Server show the configuration ...")
        logger.info("[DUT] %s" % (server_device.device_get_running_config()))
        if set_result: set_result = Dialer_RRC_Check(server_device) #Dialer should be on 4G mode, 3G not support RRC state.
        if set_result: set_result = Dialer_Simlot_Change(server_device)

        logger.info("[DUT]Celluar Basic Test Finished")
        if set_result:
            if "STS" in Server_Type:
                set_result = Dialer_firmware_switch(server_device)

    server_device.device_send_command("reboot")
    logger.info("[DUT]Celluar Test Finished as %s" %(set_result))
    #sqamail = sqa_mail()
    #sqamail.send_mail("lance.chien@lileesystems.com", "Celluar Test %s"%(set_result), u"%s" %(set_result))
