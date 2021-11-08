from datetime import datetime
import os
import boto3


s3 = boto3.client('s3')
anf = boto3.client('network-firewall')

timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
today_date = datetime.now().strftime("%Y%m%d")

suricata_rulegroup_prefix="suricata"
rulegroup_type="STATEFUL"

def get_rulegroups_summary(rulegroups):
    total_rule_count = 0
    total_rulegroup_capacity = 0
    for rulegroup in rulegroups:
        response = anf.describe_rule_group(
            RuleGroupName=rulegroup["Name"],
            RuleGroupArn=rulegroup["Arn"],
            Type=rulegroup_type)
        
        rulestring = response["RuleGroup"]["RulesSource"]["RulesString"]
        rulegroup_capacity = response["RuleGroupResponse"]["Capacity"]
        rules=rulestring.splitlines()
        print(rulegroup["Name"]+" : " + str(len(rules)) + " / " + str(rulegroup_capacity))
        total_rule_count = total_rule_count + len(rules)
        total_rulegroup_capacity = total_rulegroup_capacity + int(rulegroup_capacity)
    print("Total Rule Count : ", total_rule_count)
    print("Total RuleGroup Capacity : ", total_rulegroup_capacity)



def lambda_handler(event, context):
    
    response = anf.list_rule_groups()
    rgs = response["RuleGroups"]
    
    suricata_rulegroup_list = [ rg for rg in rgs if rg["Name"].startswith(suricata_rulegroup_prefix) ]
    all_rulegroup_list = [ rg for rg in rgs ]
    
    get_rulegroups_summary(suricata_rulegroup_list)
    
    

