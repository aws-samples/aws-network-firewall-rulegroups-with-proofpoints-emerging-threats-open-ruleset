# 
# Lambda Function Name: ANFConvertIDStoIPS
# Important Note: This function gets triggered by a S3 put object action in <anf_bucket>/extracted/ids_to_ips/ folder. 
#                 This function assumes the placed file is already processed by ANFSuricataRulesProcessor lambda function and
#                 the ruleset is fully compatible with AWS Network Firewall. Converts any rules with action = alert to action = drop
#
#


from datetime import datetime
import os
import boto3
import math
from suricataparser import parse_rule, parse_file


s3 = boto3.client('s3')
anf = boto3.client('network-firewall')
ec2 = boto3.client('ec2')

timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
today_date = datetime.now().strftime("%Y%m%d")

RuleGroupType = "STATEFUL"

def check_rule_group_exists(RuleGroupName):
    try:
        RuleGroup = anf.describe_rule_group(
                        RuleGroupName=RuleGroupName,
                        Type=RuleGroupType
                        )
    except Exception as ResourceNotFoundException:
        return False
    except Exception as err:
        # Raise exception for any other errors
        raise err
    else:
        return True

def get_rule_group(RuleGroupName):
    RuleGroup = anf.describe_rule_group(
                    RuleGroupName=RuleGroupName,
                    Type=RuleGroupType
                    )
    return RuleGroup


def save_rulesets(ruleset,bucket,filename,prefix):

    folder='processed_rules/'+today_date+'/'+prefix+'/'
    fcontent = "\n".join([ str(rule) for rule in ruleset ])
    try:
        response = s3.put_object(
            Bucket=bucket,
            Key=folder+timestamp+'-'+filename+'.txt',
            Body=fcontent
            )
    except Exception as err:
        raise err

def convert_ids_ips(ruleset):
    ips_rules = []
    for rule in ruleset:
        # Function assumes the passed ruleset is already processed by ANFSuricataRulesProcessor lambda and has valid ruleset compatible with ANF
        if rule.action == "alert": 
            ips_rule = str(rule).replace("alert","drop",1)
            parsed_rule = parse_rule(ips_rule)
            ips_rules.append(parsed_rule)
        else:
            ips_rules.append(rule)

    return ips_rules


def lambda_handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']


    suricata_rules_filename = key.split('/')[-1].split('.')[0].replace('_','-')
    s3.download_file(bucket, key, '/tmp/'+suricata_rules_filename)
    
    content=parse_file('/tmp/'+suricata_rules_filename) 
    print("Converting Suricata Rules file from IDS to IPS ruleset: s3://"+bucket+"/"+key)
    ruleset = [ rule for rule in content if rule.enabled == True ]
    rule_count = len(ruleset)
    
    if rule_count == 0 :
        print("SKIPPING RULE FILE: No Valid Rules found that can be applied to ANF for file :", suricata_rules_filename)
        save_rulesets(ruleset,bucket,suricata_rules_filename,'EMPTY')
        exit()
    
    ips_ruleset = convert_ids_ips(ruleset)
    
    # Roundup to nearest hundred with 30% buffer
    RuleGroupCapacity = int(math.ceil((len(ips_ruleset) * 1.3) / 100.0)) * 100
    
    # Create/Update RuleGroup per each ruleset chunk
    RuleGroupName="ips-suricata-"+suricata_rules_filename
    RulesString = "\n".join([ str(rule) for rule in ips_ruleset ])
    
    if check_rule_group_exists(RuleGroupName):
        RuleGroup=get_rule_group(RuleGroupName)
        UpdateToken=RuleGroup["UpdateToken"]
        print("Attempting Update RuleGroup: "+RuleGroupName+ " with " + str(len(ips_ruleset)) + " rules" )
        
        try:
            response = anf.update_rule_group(
                            RuleGroupName=RuleGroupName,
                            Type=RuleGroupType,
                            Rules=RulesString,
                            UpdateToken=RuleGroup["UpdateToken"]
                        )
            print(response)
            save_rulesets(ips_ruleset,bucket,RuleGroupName,'APPLIED')
        except Exception as err:
            save_rulesets(ips_ruleset,bucket,RuleGroupName,'ERROR')
            raise err
    else:
        print("Attempting Create RuleGroup: "+RuleGroupName+ " with " + str(len(ips_ruleset)) + " rules" )
        try:
            response = anf.create_rule_group(
                            RuleGroupName=RuleGroupName,
                            Type=RuleGroupType,
                            Rules=RulesString,
                            Capacity=RuleGroupCapacity
                        )
            print(response)
            save_rulesets(ips_ruleset,bucket,RuleGroupName,'APPLIED')
        except Exception as err:
            save_rulesets(ips_ruleset,bucket,RuleGroupName,'ERROR')
            raise err