import os
import requests
import boto3
import hashlib
import tarfile
from urllib.parse import urlparse
from io import BytesIO


# boto3 

ssm = boto3.client('ssm')
s3 = boto3.client('s3')


# import lambda variables

bucket = os.environ["SuricataRulesBucket"]
SuricataRulesetVersion = os.environ["SuricataRulesetVersion"].strip()
SuricataUpdateCheckUrl = os.environ["SuricataUpdateCheckUrl"]
SuricataRulesetDownloadUrl = os.environ["SuricataRulesetDownloadUrl"]
SuricataRulesetUpdateCheckSSMParam = os.environ["SuricataRulesetUpdateCheckSSMParam"]

# define some global variables

ruleset_folder = "ruleset_tarballs/"
extracted_folder = "extracted/"


def  get_deployed_ruleset_version_from_ssm(ssmparam):
    try:
        response = ssm.get_parameter(
            Name=ssmparam,
            WithDecryption=False
            )
    except Exception as err:
        raise err

    return response["Parameter"]["Value"]

def get_current_ruleset_version_from_url(url):
    try:
        response = requests.get(url)
    except Exception as err:
        raise err

    return response.content.decode('utf-8').rstrip()

def download_ruleset(ruleset_url,url_version):
    try:
        print("Downloading latest ruleset from: ",ruleset_url)
        
        ruleset_tar_gz = ruleset_url.rsplit('/')[-1]
        ruleset_key = ruleset_folder+str(url_version)+'/'+ruleset_tar_gz
        
        response = requests.get(ruleset_url)
        orig_md5 = requests.get(ruleset_url+'.md5').content.decode('utf-8').rstrip()
        response_md5 = hashlib.md5(response.content).hexdigest()
        
        if orig_md5 == response_md5: 
            print("Verified md5 checksum. Saving file to s3")
        
            # with open(ruleset_tar_gz, "wb") as file:
            #     file.write(response.content)

            s3upload = s3.put_object(
                Bucket=bucket,
                Key=ruleset_key,
                Body=response.content
                )
            # save md5 as well
            s3upload = s3.put_object(
                Bucket=bucket,
                Key=ruleset_key+".md5",
                Body=orig_md5
                )
            saved_file = "s3://"+bucket+"/"+ruleset_key
            print("Saved files: "+saved_file +" md5: " + saved_file + ".md5" )
        else:
            print("md5 checksum mismatch." + str(orig_md5) + " vs " + str(response_md5) )
    except Exception as err:
        raise err
    
    return saved_file
    

def extract_ruleset(saved_file):
    
    temp_folder = "/tmp/suricata/"
    s = urlparse(saved_file)
    s3bucket = s.netloc
    key = s.path.lstrip('/')
    folder = extracted_folder
    
    print("Downloading "+ saved_file + " for processing")
    fileobj=BytesIO(s3.get_object(Bucket=s3bucket,Key=key)['Body'].read()) 
    
    tar = tarfile.open(mode="r:gz", fileobj = fileobj)
    tar.extractall(temp_folder)
    for f in tar:
        if f.isfile():
            print("Extracting file : " + f.name)
            fcontent = open(temp_folder+f.name).read()
            s3upload = s3.put_object(Bucket=s3bucket,Key=folder+f.name,Body=fcontent)

def update_version_in_ssm(ssmparam,value):
    ssm.put_parameter(
        Name=ssmparam,
        Value=str(value),
        Type="String",
        Overwrite=True
        )

def lambda_handler(event, context):
    url_version = int(get_current_ruleset_version_from_url(SuricataUpdateCheckUrl))
    ssm_version = int(get_deployed_ruleset_version_from_ssm(SuricataRulesetUpdateCheckSSMParam))
            
    print("Current Ruleset Version: ", ssm_version)
    
    if url_version > ssm_version :
        print("Found updated ruleset version: " + str(url_version) + ". Downloading updated rulesets for processing")
        
        ruleset_url = SuricataRulesetDownloadUrl.replace("VERSION",SuricataRulesetVersion)
        
        saved_file = download_ruleset(ruleset_url,url_version)
        extract_ruleset(saved_file)
        update_version_in_ssm(SuricataRulesetUpdateCheckSSMParam,url_version)
    else:
        print("Deployed ruleset version : " + str(ssm_version) + " is not greater than online version: " + str(url_version) +" \n Skipping Ruleset Update")
        
    