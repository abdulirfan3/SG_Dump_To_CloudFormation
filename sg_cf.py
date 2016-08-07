#!/usr/bin/python
# PARAMETER(S): NONE
#
# AUTHOR:       Abdul Mohammed 
#
# Requirements:  
#                Requires Troposphere (https://github.com/cloudtools/troposphere)
#                Requires Boto
#                
#
# DESCRIPTION:  This script will create a file that will
#               output a cloud formation template for all the SG.
#               Additinally you can send the output file to S3 bucket as backup
#######################################################################
import boto.ec2
import sys
import time
import re
import subprocess
import troposphere.ec2 as tec2

from boto.vpc import VPCConnection
from troposphere import Template

# Open a File called output_Current_time to write all log output
curr_time = time.strftime("%Y-%b-%d__%H_%M_%S",time.localtime())
output_file = open('output_'+curr_time+'.log', 'w')
fn = 'output_'+curr_time+'.log'
# Send all standout output to output_file
sys.stdout = output_file

region = "us-east-1"

# re_data function, that will be used later to return port, proto, cidr by passing in a string
def re_data(data):
    # 2 Capture group, first one getting proto and second one getting port/range
    prt_rgx = re.compile(r'(\w+)\((\S+-\S+)\)')
    # Capture CIDR
    cidr_rgx = re.compile(r'\[(.*?)\]')
    discard, protoport, cidr = data.rsplit(":", 2)
    port_find = prt_rgx.search(protoport)
    proto, port = port_find.group(1), port_find.group(2)
    cidr_find = cidr_rgx.search(cidr)
    cidr = cidr_find.group(1)
    #print port, proto, cidr #-- Debug
    # AWS uses "-1--1" for all ICMP traffic and "NONE-NONE" for all traffic
    if port == "None-None" or port == '-1--1': 
        port = -1
    # setting protocol to -1, when inbound traffic is set to "all traffic"    
    if proto == "1":
        proto = "-1"
    return dict(port=port, proto=proto, cidr=cidr)

# makesg funtion to build list of dictionary for Ingress rule for SG
def makesg(cidr, proto, ports):
    sg = dict()
    # Loop through list of ports, that will come out a list
    for port in ports:
        # assign fromport - toport using split function (for port that are have range like 0-80)
        if type(port) is not int and '-' in port:
            [fromport, toport] = port.split('-')
        # if port does not have a range, then assign fromport - toport to exactly the same thing 
        # Example, (port is only 80, in this case fromport = 80, toport = 80)    
        else:
            fromport = port
            toport = port
        # When you have one SG referencing another SG, then we use below logic to define our ingress rules
        # cidr changes from 'x.x.x.x/x' to sg-sgid-actid
        if cidr.startswith('sg-'):
            # 2 capture group, first one catching the sgid and second one catching account id
            cidr_sp_re = re.compile(r'(sg-\w{8})-(\d{12})')
            cidr_sp_match = cidr_sp_re.search(cidr)
            sgid, sgact = cidr_sp_match.group(1), cidr_sp_match.group(2)
            #print sgid, sgact # --Debug
            # Ingress rule when SG start with 'sg-', as this requires groupid and groupownerid
            sg = tec2.SecurityGroupRule(
                IpProtocol = proto,
                FromPort = fromport,
                ToPort = toport,
                SourceSecurityGroupId = sgid,
                SourceSecurityGroupOwnerId = sgact
            )
        else:
            # Ingress rule when SG does NOT start with 'sg-'  
            sg = tec2.SecurityGroupRule(
                IpProtocol = proto,
                FromPort = fromport,
                ToPort = toport,
                CidrIp = cidr
            )      
    return sg  

# Use Boto to get a list of all VPC
# AWS access_key_id/secret_access_key can go below, if the server does not have appropriate IAM role assigned
# something like below comment, same thing applies to any boto command connect_to_region
# vpccon = VPCConnection(aws_access_key_id='XXXXXXXXXXXXXX', aws_secret_access_key='XXXXXXXXX').get_all_vpcs()
vpccon = VPCConnection().get_all_vpcs()
# By default the output is a list, so we convert it to string and use the split function
# to get the actual VPC-ID, default output is something like "VPC:vpc-xxxxxxxx"
for v in vpccon:
    vpcstr = str(v)
    vpcid = vpcstr.split(':')[1]
    print "#" * 100  
    print "                                          VPCID:" + vpcid + "                                               "
    print "#" * 100 
    # Set the main loop filter to the VPCID and connect to the region and get all SG based on VPCID filter
    fts = {'vpc-id': vpcid} 
    sgconn = boto.ec2.connect_to_region(region).get_all_security_groups(filters=fts)
    #mc - main connect/loop
    for mc in sgconn:
        # Inside of main loop, set filter, so we are only accessing SG related to that VPC
        fts = {'vpc-id': vpcid, 'group-id': mc.id}
        sgs = boto.ec2.connect_to_region(region).get_all_security_groups(filters=fts)
        for sg in sgs:
            # build a new list for each SG 
            mylist = []
            # build a string that will be used by re_data function to strip of everything and get "port, proto, cidr"
            for rule in sg.rules:
                # If a inbound rule has policy that allows all traffic, all protocol, all port ranges then cidr/grant
                # is grouped together as below, to avoid that we use a simple logic to break that down into single
                # line to create our list for that SG
                # (SecurityGroup:SG_NAME, u'sg-xxxxxxx', 'inbound:', IPPermissions:-1(None-None), ' source:', [1.1.1.1./32, 2.2.2.2/32, 3.3.3.3/32, 4.4.4.4/32])
                if len(rule.grants) > 1:
                    for grant in rule.grants:
                        st = sg, sg.id, "inbound:", rule, " source:", [grant]
                        #print st
                        # without the below, we get a commas(,) and we need to replace commas with space
                        # in our string as this is not part of our re_data function(which use a Regex processor) 
                        s = str(st).replace(","," ")
                        jt = re_data(s)
                        mylist.append(jt)
                else:
                    st = sg, sg.id, "inbound:", rule, " source:", rule.grants
                    #print st
                    s = str(st).replace(","," ")
                    jt = re_data(s)
                    mylist.append(jt)
        #print mylist #-- Debug, outer loop 
        # Start of troposphere logic       
        VPC = vpcid
        template = Template()
        print ""
        # if we do not convert this to string, it will be treated as list
        # SG name comes out as "SecurityGroup:sg name", so we use split function to get actual sg name
        sgname_str = str(sg)
        sgname = sgname_str.split(':')[1]
        # Cloud formation has a limitation - where property name cannot have Underscore, dashes or spaces
        # so we use below to replace that and change "sg_name with-space" to "sgnamewithspace"
        rs_name = sgname.replace('_',' ').replace('-',' ').replace(' ', '')
        print "SecurityGroup Name:"
        print sgname
        print ""
        tsg = tec2.SecurityGroup(rs_name)
        tsg.GroupDescription = sg.description
        tsg.SecurityGroupIngress = []
        # Create an empty list called "tsg.SecurityGroupIngress" and append to that list, which in turn
        # creates a dictionary from the Makesg function used by Cloud formation, something like below
        """
        {
            "CidrIp": "x.x.x.x/x",
            "FromPort": "110",
            "IpProtocol": "tcp",
            "ToPort": "110"
          },
          {
            "CidrIp": "x.x.x.x/x",
            "FromPort": "0",
            "IpProtocol": "tcp",
            "ToPort": "443"
          }
         """ 
        for lst in mylist:
            tsg.SecurityGroupIngress.append(makesg(lst['cidr'], lst['proto'], [lst['port']]))
        # add vpcid and template resources to troposphere and print out JSON syntax    
        tsg.VpcId=VPC
        template.add_resource(tsg)
        print template.to_json()


# Get a list of Servers and which SG attached to each server
print "#" * 30  
print "List of instances and SG attached"     
print "#" * 30  
print ""
# reservation list:
conn = boto.ec2.connect_to_region(region)
inst = conn.get_all_instances()

# go through instance list:
for sr in inst:
# check how many SGs are attached to instance
    sg_num = len(sr.instances[0].groups)
    print "######################\n"
    # Print instance-id, Tags and Number of SG attached to that instance
    print sr.instances[0]
    print "Tags:", sr.instances[0].tags
    print "Number of SGs attached: %s\n" % sg_num
# go through each SG
    for name in range(sg_num):
# find id for each SG
        group_id = sr.instances[0].groups[name].id
        sg_name = conn.get_all_security_groups(group_ids=group_id)[0]
# print SG name
        print sg_name

#Close file
output_file.close()

# Sending output file to S3 bucket called "BUCKET-NAME"
# Below relies on aws cli installed on OS, not using "shell=True" for subprocess module 
# The behavior of the shell argument can sometimes be confusing and hence good to avoid
subprocess.call(['aws', 's3', 'mv', fn, 's3://BUCKET-NAME/SG-CF-Backup/', '--sse']) 
