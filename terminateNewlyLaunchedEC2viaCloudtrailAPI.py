import boto3
import logging
import json
import datetime


def lambda_handler(event, context):
    print datetime.datetime.now()
    client = boto3.client('cloudtrail')
    ec2 = boto3.resource('ec2')
    response = client.lookup_events(
        #RunInstances is an event name related to launching new instance.
        #response is a dict containing all attributes related to RunInstances event, i.e. user, sourceIP, VPC, instanceId, etc
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': 'RunInstances'
            },
        ],
        #As cloudtrail may have too many irrelevant 'RunInstances' events in event history, here I only want to terminate newly launched instances by other user not to affect the existing running instances.
        #This script will be invoked every 15 minutes and the cloudtrail event history updates after the event is created.
        #To look up more relevant events and avoid miss the events, I search the range of 35 mins in cloudtrail event history (15mins[cloudtrail update delay time] + 15mins[ lambda execution frequency] +5 mins[buffer])
        StartTime=datetime.datetime.now() - datetime.timedelta(minutes=35),
        EndTime=datetime.datetime.now()
    )
    
    for singleEvent in response['Events']:
        #singleEvent['CloudTrailEvent'] is an unicode string, so we need to convert to dict type
        singleCloudTrailEvent = json.loads(singleEvent['CloudTrailEvent'])
        #ids is the list to store instanceId to terminate
        ids = []
        #extract the element from cloudtrail log to find the instanceId 
        for singleItem in singleCloudTrailEvent['responseElements']['instancesSet']['items']:
            ids.append(singleItem['instanceId'])
            print str(singleItem['instanceId'])
            print singleItem['instanceId']
        #terminate ec2 use filters function
        terminateInstance = ec2.instances.filter(InstanceIds=ids).terminate()
        #output EC2 terminate log
        print terminateInstance
            