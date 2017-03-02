# Automation
Automation library and script for console and ssh to device.

## lib
The every function had been introduced how to use the class to implement the function in the example of main.
So you could refer these the library to generate script in the test.
- Configuration.py: the generator of cli command like: add vlan, wifi and celluar 
  ### example:
      configlist = list()
      function = Function("vlan")
      configlist.extend(function.get_vlan(vlan_index, vlan_description_list[index], ip_mode, ipaddress_list[index], netmask))

- Device.py : the control of device with ssh or telnet type.
  ### example
      - telnet : device =Device_Tool("10.2.11.58",2041,"telnet","admin","admin","device_test")
      - ssh:   : device =Device_Tool("10.2.52.53",22,"ssh","admin","admin","device_test")
      - command :
                 1.device.device_send_command("config app-engine 0 enable")
                 2.checkresult = device.device_send_command_match("show interface all",5,"vlan 100 && up")

- TelnetConsole.py: the control of device with telnet type.
  ### example
         telnetconsole =Telnet_Console('10.2.11.58',2035,"admin","admin","telnet_test")
         telnetconsole.login()
- SSHConsole.py:the control of device with ssh type.
  ### example
         sshconnect = SSHConnect("10.2.52.53")
         sshconnect.connect()
         
- TestRail.py: the update of test result to testrail.
  ### example
        mainlogger = Log("TestrailLog","main")
        project_name ="LileeOS"
        test_plan = "LileeOS 3.3.2 Auto Regression Test"
        test_run = "Switch"
        device_type = "DTS"
        test_id = 6904
        buildversion = "3.3_build60"
        result ="Passed"
        comment = "Auto test passed"
        testrail =TestRailAPI(logname="main")
        result = testrail.update_test_result(project_name,test_plan,test_run,device_type,test_id,buildversion,result,comment,True)
        mainlogger.write("info",result)
        
- Image.py: the image update for device
  ### example
      mainlogger = Log("Image_Tool","Image_Tool")
      image_server = "10.2.10.17"
      imaage_version = '3.3'
      image_mode = 'Target'
      image_build_no ="63"
      deviceip = '10.2.52.53'
      deviceport = 22
      device_connect_type = "ssh"
      username ="admin"
      password ="admin"

      item = list()
      maintain_interface ="maintenance 0"
      maintain_ip= '10.2.52.53'
      maintain_netmask ='255.255.252.0'
      maintaince_ip_mode ="static"
      imagetool =ImageTool(deviceip,deviceport,device_connect_type,username,password)
      imagetool.set_image_host(image_server,imaage_version,image_mode,image_build_no)
      imagetool.upgrade_device_image(maintain_interface,maintaince_ip_mode,maintain_ip,maintain_netmask)
      
- Tool.py: the other tool library for supporting the testing.


## test
- Pretesting:this script of testing is just for initial testing for every build.
- Function:this script of testing is just for  basic testing for every build.
- System:this script of testing is just for long term or complex setting testing.
- POC:this test script of testing is just for the verification of customer request.
- Other:this test script of testing is just for the verification fo special case like issue check.


##Run locally
- Install requirements: `pip install -r requirements.txt`


