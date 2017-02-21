from lib.Device import *
from lib.Configuration import *
import logging
import os
import sys
from time import gmtime, strftime


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

logfilename = "user%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
logger = set_log(logfilename,"user_testing")

if __name__ == '__main__':
    ip ="10.2.52.54"
    port = 22
    mode ="ssh"
    username = "admin"
    password ="admin"
    device =Device_Tool(ip,port,mode,username,password,"user_testing")
    if device:
        device.device_get_version()
        logger.info("Device Bios Version:%s"%(device.bios_version))
        logger.info("Device recovery image:%s"%(device.boot_image))
        logger.info("Device build image:%s"%(device.build_image))
        device.device_send_command("update terminal paging disable")
        device.device_send_command("config app-engine 0 disable")
        userlist =["adminuser1","appengineuser1","normaluser1"]
        rolelist =["admin","app-engine-admin","user"]
        loginchecklist =["localdomain","App-Engine","localdomain"]
        common_password_secret_key ='$1$ZLUv6y1W$VjU8iObICrvO79hWOCfp11'
        change_common_password_secret_key='$1$oZaTP2GK$lQgecuyXtu6McpMlgJkOE0'
        common_password='Lilee1234'
        change_common_password='Lilee12341234'


        # Add user
        configlist = list()
        function = Function("user")
        for index,value in enumerate(userlist):
            role = rolelist[index]
            configlist.extend(function.get_user(value,common_password_secret_key,role))
        device.device_set_no_config(configlist)
        time.sleep(5)
        device.device_set_configs(configlist)


        #show user to check info and login to check.
        for index,value in enumerate(userlist):
            role = rolelist[index]
            login_check_string = loginchecklist[index]
            checkcommand = "show user"
            checkmatch = "%s | %s"%(value,role)
            checkresult = device.device_send_command_match(checkcommand,7,checkmatch)
            logger.info("[%s]check user %s and role %s result :%s"%(checkcommand,value,role,checkresult))
            if checkresult:
                sub_device = Device_Tool(ip,port,mode,value,common_password,"user_testing")
                if login_check_string in sub_device.target_response :
                    logger.info("[user login] user %s and role %s result :%s"%(value,role,"Pass"))
                else:
                    logger.info("[user login] user %s and role %s result :%s"%(value,role,"Fail"))

        #chanage user password and login to check
        for index,value in enumerate(userlist):
            role = rolelist[index]
            login_check_string = loginchecklist[index]
            change_password_command = "config user %s password %s"%(value,change_common_password_secret_key)
            checkresult = device.device_send_command(change_password_command)
            logger.info("[change user password]check user %s and role %s result :%s"%(value,role,checkresult))
            if checkresult:
                sub_device = Device_Tool(ip,port,mode,value,change_common_password,"user_testing")
                if login_check_string in sub_device.target_response :
                    logger.info("[change pwassword to user login] user %s and role %s result :%s"%(value,role,"Pass"))
                else:
                    logger.info("[change pwassword to user login] user %s and role %s result :%s"%(value,role,"Fail"))

        #no add user and show user check
        for index,value in enumerate(userlist):
            role = rolelist[index]
            device.device_send_command("no config add user %s"%(value))
            checkcommand = "show user"
            checkmatch = "%s | %s"%(value,role)
            checkresult = device.device_send_command_match(checkcommand,7,checkmatch)
            if checkresult ==False:
                logger.info("[no config add user]check user %s and role %s result :Pass"%(value,role))
            else:
                logger.info("[no config add user]check user %s and role %s result :Fail"%(value,role))


































