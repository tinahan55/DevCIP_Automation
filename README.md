# Automation
Automation library and script for console and ssh to device.

## lib
The every function had been introduced how to use the class to implement the function in the example of main.
So you could refer these the library to generate script in the test.
- Configuration.py: the generator of cli command like: add vlan, wifi and celluar 
- Device.py : the control of device with ssh or telnet type.
- TelnetConsole.py: the control of device with telnet type.
- SSHConsole.py:the control of device with ssh type.
- TestRail.py: the update of test result to testrail.
- Image.py: the image update for device
- Tool.py: the other tool library for supporting the testing.


## test
- Pretesting:this script of testing is just for initial testing for every build.
- Function:this script of testing is just for  basic testing for every build.
- System:this script of testing is just for long term or complex setting testing.
- POC:this test script of testing is just for the verification of customer request.
- Other:this test script of testing is just for the verification fo special case like issue check.


##Run locally
- Install requirements: `pip install -r requirements.txt`


