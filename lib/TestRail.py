from thirdparty.testrail import *
import logging
import os
from time import gmtime, strftime
from Tool import Log

class TestRailAPI(object):
    def __init__(self,host='https://lileesystems.testrail.net',user = "ricky.wang@lileesystems.com",password = "A@exp0lk2015"
                 ,logname=""):
        self.client = APIClient(host)
        self.client.user =user
        self.client.password=password
        self.logger = logging.getLogger('%s.testailapi'%(logname))
        self.logger.info('creating the sub log for testrailapi')

    def __get_project_list(self):
        url ='get_projects'
        projectlist = self.client.send_get(url)
        return projectlist

    def __get_test_plan(self,project_id):
        url = 'get_plans/%s'%(project_id)
        planlist = self.client.send_get(url)
        return planlist


    def __get_test_plan_detail(self,plan_id):
        url = 'get_plan/%s'%(plan_id)
        detail = self.client.send_get(url)
        return detail

    def __get_test_run(self,run_id):
        url='get_run/%s'%(run_id)
        run =self.client.send_get(url)
        print run


    def __get_tests(self,run_id):
        url='get_tests/%s'%(run_id)
        tests = self.client.send_get(url)
        return tests



    def __get_test_case(self,project_id,suite_id,section_id=None):
        url = 'get_cases/%s&suite_id=%s'%(project_id,suite_id)
        if section_id !=None:
            url = "&section_id=%s"%(section_id)
        caselist = self.client.send_get(url)
        return caselist

    def __get_test_case_detail(self,case_id):
        url = 'get_case/%s'%(case_id)
        case = self.client.send_get(url)
        return case


    def __get_results_for_case(self,run_id,case_id):
        url ='get_results_for_case/%s/%s'%(run_id,case_id)
        result =  self.client.send_get(url)
        return result

    def __get_results_for_test(self,test_id):
        url ='get_results/%s'%(test_id)
        result =  self.client.send_get(url)
        return result



    def __add_result_for_case(self,run_id,case_id,status_id,build_version,comment):
        url ='add_result_for_case/%s/%s'%(run_id,case_id)
        data ={"status_id":status_id,"version":build_version,"comment":comment,"defects":""}
        result = self.client.send_post(url,data)
        if "200" in result:
            return True
        else:
            return False
    def __add_result_for_test(self,test_id,status_id,build_version,comment):
        url ='add_result/%s'%(test_id)
        data ={"status_id":status_id,"version":build_version,"comment":comment,"elapsed":"","defects":""}
        result = self.client.send_post(url,data)
        if "200" in result:
            return True
        else:
            return False

    def __get_result_status_id(self,result_status):
        status_id =1
        if result_status == "PASS":
            status_id = 1
        elif result_status =="FAIL":
            status_id =5
        elif result_status=="N/A":
            status_id=5
        return status_id


    def __update_result(self,test_id,status_id,buildversion,comment,ifwriteable):
        try:
            resultlist = self.__get_results_for_test(test_id)
            filter_result =  list(railresult for railresult in resultlist if railresult["version"] == buildversion)
            if len(filter_result) == 0:
                try:
                    self.logger.info("[update_result]not result for this build")
                    add_result =  self.__add_result_for_test(test_id,status_id,buildversion,comment)
                    if (add_result):
                        self.logger.info("[[update_result] result: Completed.")
                except Exception,ex:
                    self.logger.error("[add result] result: Fail:(%s)"%(str(ex)))
            else:
                if ifwriteable == True:
                    self.logger.info("[update_result]update result for this build again.")
                    add_result =  self.__add_result_for_test(test_id,status_id,buildversion,comment)
                    if (add_result):
                        self.logger.info("[update_result] result: Completed.")
                    self.logger.info("[update_result] result had been existed, not need to upload:%s"%(str(len(filter_result))))

        except Exception,ex:
            self.logger.error("[update_result] result: Fail:(%s)"%(str(ex)))


    def update_test_result(self,project_name,test_plan,test_run,device_type,case_id,build_version,result,comment,ifwriteable):
        update_result = False
        self.logger.info("[update_test_result] %s,%s,%s,%s,%s,%s,%s,%s,%s"%(project_name,test_plan,test_run,device_type,case_id,build_version,result,comment,ifwriteable))
        projectlist = self.__get_project_list()
        filterproject =  list(project for project in projectlist if project["name"] == project_name)
        if filterproject!=None:
            project_id = filterproject[0]["id"]
            planlist = self.__get_test_plan(project_id)
            filterplan =  list(plan for plan in planlist if plan["name"] == test_plan)
            if filterplan!=None:
                plan_id = filterplan[0]["id"]
                detail = self.__get_test_plan_detail(plan_id)
                entity = list(entity for entity in detail["entries"] if entity["name"] == test_run)
                if entity!=None:
                    run = list(run for run in entity[0]["runs"] if run["config"] == device_type.upper())
                    print run
                    if run!=None:
                        run_id = run[0]["id"]
                        testlist = self.__get_tests(run_id)
                        test = list(test for test in testlist if test["case_id"] == case_id)
                        if test!=None:
                            status_id = self.__get_result_status_id(result)
                            case_id = test[0]["case_id"]
                            test_id = test[0]["id"]
                            print "%s,%s"%(case_id,test_id)
                            #update_result = self.__update_result(test_id,status_id,build_version,comment,ifwriteable)

            #self.logger.info("[update_test_result] result : %s"%(update_result))


            return update_result




if __name__ == '__main__':
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
