from datetime import datetime
import os
import boto3
import math
from suricataparser import parse_rule, parse_file


s3 = boto3.client('s3')
anf = boto3.client('network-firewall')
ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')

timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
today_date = datetime.now().strftime("%Y%m%d")

# Refer: https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html#suricata-example-rule-with-variables
AllowedRuleVariables=["EXTERNAL_NET","HOME_NET","HTTP_PORTS", "HTTP_SERVERS", "DNS_SERVERS"]

# Define Static Rule Variables
# Must be valid values in proper format for these to work. 
# Refer: https://suricata.readthedocs.io/en/suricata-6.0.2/rules/intro.html for valid formats
# Eg: HTTP_PORTS  = [80,443,8080]
#     DNS_SERVERS = [10.0.0.2]
#     HTTP_SERVERS = [10.0.0.5,10.0.0.6] # list of webserver ips

HTTP_PORTS = os.environ["HTTP_PORTS"]
HTTP_SERVERS = os.environ["HTTP_SERVERS"] 
DNS_SERVERS = os.environ["DNS_SERVERS"] 


StaticRuleVariables= {
    "$HTTP_PORTS" : HTTP_PORTS,
    "$HTTP_SERVERS" : HTTP_SERVERS,
    "$DNS_SERVERS": DNS_SERVERS,
}

RuleGroupType = "STATEFUL"
ConvertRuleGroupIDStoIPSSSMParam = os.environ["ConvertRuleGroupIDStoIPSSSMParam"]


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

def process_ruleset(ruleset):
    
    dropped_rules = []

    # https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html
    # The following Suricata features are not supported by Network Firewall: (as of May 2021)
    # ------------------------------------------------------------------------------------
    #
    # 
    # IP reputation. The iprep keyword is not allowed. 
    # Lua scripting.
    # GeoIP.
    # File extraction. File keywords aren't allowed.
    # ENIP/CIP keywords.
    # Datasets. The keywords dataset and datarep aren't allowed.
    # Rules actions except for pass, drop, and alert. Pass, drop, and alert are supported.
    
    for rule in ruleset:

        # Rules actions except for pass, drop, and alert. Pass, drop, and alert are supported
        if rule.action not in ["alert", "drop" , "pass"]:
            rule.enabled = False
            dropped_rules.append(rule)
            continue
        
        # IP reputation. The iprep keyword is not allowed.  -- drop rules with iprep keyword
        if len(rule.get_option("iprep")) > 0:
            rule.enabled = False
            dropped_rules.append(rule)
            continue
        # Lua scripting.  -- drop rules with luajit keyword
        if len(rule.get_option("luajit")) > 0 or len(rule.get_option("lua")) > 0 :
            rule.enabled = False
            dropped_rules.append(rule)
            continue
        # GeoIP - TBD yet to find the keyword
        
        # File extraction. File keywords aren't allowed.
        if len(rule.get_option("filename")) > 0 or len(rule.get_option("fileext")) or len(rule.get_option("filemagic")) or len(rule.get_option("filestore")) or len(rule.get_option("filemd5")) or len(rule.get_option("filesha1")) or len(rule.get_option("filesha256")) or len(rule.get_option("filesize")) :
            rule.enabled = False
            dropped_rules.append(rule)
            continue

        # ENIP/CIP keywords.  -- drop rules with enip_command,cip_service keyword
        if len(rule.get_option("enip_command")) > 0 or len(rule.get_option("cip_service")) > 0 :
            rule.enabled = False
            dropped_rules.append(rule)
            continue
        
        # Datasets. The keywords dataset and datarep aren't allowed..  -- drop rules with enip_command,cip_service keyword
        if len(rule.get_option("dataset")) > 0 or len(rule.get_option("datarep")) > 0 :
            rule.enabled = False
            dropped_rules.append(rule)
            continue
        
        # Rule files with flowbits:isset are failing if the same file does not contain rules flowbits:set statements the flowbits:isset refers to
        # Dropping rules with flowbits:isset to process more rules until we find a permanent alternative
        
        if "flowbits:isset" in str(rule):
            rule.enabled = False
            dropped_rules.append(rule)
            continue

    
    valid_rules = [ rule for rule in ruleset if rule.enabled == True ]

    return valid_rules, dropped_rules
        

def replace_rule_vars_with_values(ruleset,dropped_ruleset):
    # Drop Rules with undefined RuleVariables. Expand AllowedRuleVariables and define them if specific RuleVariables need to be allowed
    new_ruleset = []
    for rule in ruleset:
        rule_str = str(rule)
        rulevars=[word for word in rule_str.split()[:7] if ('$' in word) ]
        for v in rulevars:
            v = v.replace('$','').replace('!','') 
            if v not in AllowedRuleVariables:
                rule_str = "# "+ rule_str # Comment the rule when parsed rule.enabled attribute is set to False. 
                dropped_ruleset.append(rule)
            else:
                for key,val in StaticRuleVariables.items():
                    rule_str = rule_str.replace(key,val)
        new_ruleset.append(parse_rule(rule_str))
    return new_ruleset,dropped_ruleset

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

def trigger_ids_to_ips(ruleset,bucket,filename):

    folder='extracted/ids_to_ips/'
    fcontent = "\n".join([ str(rule) for rule in ruleset ])
    try:
        response = s3.put_object(
            Bucket=bucket,
            Key=folder+filename+'.rules',
            Body=fcontent
            )
    except Exception as err:
        raise err
def  get_rulegroups_to_convert(ssmparam):
    try:
        response = ssm.get_parameter(
            Name=ssmparam,
            WithDecryption=False
            )
    except Exception as err:
        raise err

    return response["Parameter"]["Value"]

def split_files(ruleset,count,suricata_rules_filename,bucket):

    split_ruleset = [ruleset[i:i + count] for i in range(0, len(ruleset), count)]
    for index in range(len(split_ruleset)):
        fcontent = "\n".join([ str(rule) for rule in split_ruleset[index] ])
        filename = suricata_rules_filename+'-'+str(index+1).zfill(2)+'.rules'
        folder   = "extracted/rules/"
        
        try:
            response = s3.put_object(
                Bucket=bucket,
                Key=folder+filename,
                Body=fcontent
                )
            print("Saving split file to s3://"+bucket+"/"+folder+filename)
        except Exception as err:
            raise err


def lambda_handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']


    # bucket = os.environ["SuricataRulesBucket"]
    # key = "rules/emerging-imap.rules"  
    
    suricata_rules_filename = key.split('/')[-1].split('.')[0].replace('_','-')
    s3.download_file(bucket, key, '/tmp/'+suricata_rules_filename)
    
    content=parse_file('/tmp/'+suricata_rules_filename) 
    print("Processing Suricata Rules file : s3://"+bucket+"/"+key)
    print("Initial Suricata Rules count including commented rules (excluding commented headers): ", len(content))
    # Drop commented / disabled rules
    initial_ruleset = [ rule for rule in content if rule.enabled == True ]
    print("Initial Suricata Rules count (uncommented rule lines): ", len(initial_ruleset))

    # When testing with 3000+ rules faced lamdba timeout issues
    # If file contains more than 1000 active rules split into multiple files to avoid lamdba timeout issues
    
    if len(initial_ruleset) > 1000:
        print("Initial Rule Count > 1000. Spliting files by 1000 rules to process them individually")
        split_files(initial_ruleset,1000,suricata_rules_filename,bucket)
        exit()

    valid_ruleset, dropped_ruleset = process_ruleset(initial_ruleset)
    valid_ruleset, dropped_ruleset = replace_rule_vars_with_values(valid_ruleset,dropped_ruleset)
    # Drop Rules with undefined RuleVariables
    final_ruleset = [ rule for rule in valid_ruleset if rule.enabled == True ]
    final_rule_count = len(final_ruleset)
    print("Valid Rule count that can be applied to ANF: ", final_rule_count)
    print("Dropped Rule count that cannot be applied to ANF: ", len(dropped_ruleset))
    
    save_rulesets(final_ruleset,bucket,suricata_rules_filename,'FINALBEFOREAPPLY')
    save_rulesets(dropped_ruleset,bucket,suricata_rules_filename,'DROPPED')
    
    # Calculate required rule group capacity
    if final_rule_count == 0 :
        print("SKIPPING RULE FILE: No Valid Rules found that can be applied to ANF for file :", suricata_rules_filename)
        save_rulesets(final_ruleset,bucket,suricata_rules_filename,'EMPTY')
        exit()
    
    # if 1 <= final_rule_count <= 80:
    #     RuleGroupCapacity = 100
    # if 81 <= final_rule_count <= 400:
    #     RuleGroupCapacity = 500
    # if final_rule_count > 401:
    #     RuleGroupCapacity = 1000
    
    # Roundup to nearest hundred with 30% buffer
    RuleGroupCapacity = int(math.ceil((final_rule_count * 1.3) / 100.0)) * 100
    
    # Create/Update RuleGroup per each ruleset chunk
    RuleGroupName="suricata-"+suricata_rules_filename
    RulesString = "\n".join([ str(rule) for rule in final_ruleset ])

    # To convert any IDS Rulegroup to IPS Rulegroup
    # Lambda checks ssm param : ConvertRuleGroupIDStoIPS for list of suricata rulegroups to create/update respective ips rulegroups
    ids_ips_convert_list = [x.strip() for x in get_rulegroups_to_convert(ConvertRuleGroupIDStoIPSSSMParam).split(",")] 

    if check_rule_group_exists(RuleGroupName):
        RuleGroup=get_rule_group(RuleGroupName)
        UpdateToken=RuleGroup["UpdateToken"]
        print("Attempting Update RuleGroup: "+RuleGroupName+ " with " + str(len(final_ruleset)) + " rules" )
        
        try:
            response = anf.update_rule_group(
                            RuleGroupName=RuleGroupName,
                            Type=RuleGroupType,
                            Rules=RulesString,
                            UpdateToken=RuleGroup["UpdateToken"]
                        )
            print(response)
            save_rulesets(final_ruleset,bucket,RuleGroupName,'APPLIED')
            if RuleGroupName in ids_ips_convert_list:
                trigger_ids_to_ips(final_ruleset,bucket,RuleGroupName)

        except Exception as err:
            save_rulesets(final_ruleset,bucket,RuleGroupName,'ERROR')
            raise err
    else:
        print("Attempting Create RuleGroup: "+RuleGroupName+ " with " + str(len(final_ruleset)) + " rules" )
        try:
            response = anf.create_rule_group(
                            RuleGroupName=RuleGroupName,
                            Type=RuleGroupType,
                            Rules=RulesString,
                            Capacity=RuleGroupCapacity
                        )
            print(response)
            save_rulesets(final_ruleset,bucket,RuleGroupName,'APPLIED')
            if RuleGroupName in ids_ips_convert_list:
                trigger_ids_to_ips(final_ruleset,bucket,RuleGroupName)
        except Exception as err:
            save_rulesets(final_ruleset,bucket,RuleGroupName,'ERROR')
            raise err


    # Sample working RuleString Format for manual testing
    # RulesString1="""
    # alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:\"GPL IMAP rename overflow attempt\"; flow:established,to_server; content:\"RENAME\"; nocase; isdataat:100,relative; pcre:\"/\sRENAME\s[^\\n]{100}/smi\"; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2101903; rev:9; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
    # alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:\"GPL IMAP find overflow attempt\"; flow:established,to_server; content:\"FIND\"; nocase; isdataat:100,relative; pcre:\"/\sFIND\s[^\\n]{100}/smi\"; reference:bugtraq,1110; reference:cve,2000-0284; reference:nessus,10374; classtype:misc-attack; sid:2101904; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
    # """

