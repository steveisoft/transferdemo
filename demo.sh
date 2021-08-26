#!/bin/bash

monitor() {
    # performs a 'tail' on stack activity
    mkdir -p OUT
    # arg1: stack-name
    aws cloudformation describe-stacks --stack-name $1 > OUT/$1.out 2> OUT/$1.err

	if [ $? -ne 0 ]; then
		 tail -1 OUT/$1.err | cut -d: -f1
		 return
	fi

	state=$(jq -r .Stacks[0].StackStatus OUT/$1.out)

	if [ ${state/*_COMPLETE/DONE} = "DONE" ]; then
		 echo $state
		 return
	fi

	LASTEV=""
	while :
	do
		aws cloudformation describe-stack-events --stack-name $1 > OUT/$1.events.out
		if [ $? -ne 0 ]; then
			echo jq -r .Stacks[0].StackStatus $OUT/$1.events.out
			return
		fi

		LAST=$(jq .StackEvents[0].EventId OUT/$1.events.out)
		if [ "$LAST" != "$LASTEV" ]; then
			# display the last event, not seen before
			jq .StackEvents[0] OUT/$1.events.out
		fi

		LASTEV=$LAST
		stacks=`jq -r '.StackEvents[] | select(.ResourceType=="AWS::CloudFormation::Stack").PhysicalResourceId' OUT/$1.events.out | sort -u`

		master=""

		for res in $stacks
		do

			stack=$(cut -d/ -f2 <<<$res)
			#display status
			aws cloudformation describe-stacks --stack-name $stack > OUT/$1.events.out
			state=$(jq -r .Stacks[0].StackStatus OUT/$1.events.out)
			SPC=""
			if [ $stack != $1 ]; then
			   SPC="    "
			   aws cloudformation describe-stack-events --stack-name $stack > OUT/$1-sub-$stack.out
			   if [ $? -ne 0 ]; then
				   master=QUIT_COMPLETE
				   break
			   fi

			   LASTSUB=$(jq -r .StackEvents[0] OUT/$1-sub-$stack.out)
			   if [ "$LASTSUB" != "$LASTSUBEV" ]; then
				   # display the last event, not seen before
				   jq .StackEvents[0] OUT/$1-sub-$stack.out
			   fi

			   LASTSUBEV=$LASTSUB
			else
			   master=$state
			fi

			echo "$SPC $stack $state"
		done

		if [ "${master/*_COMPLETE/DONE}" = "DONE" ]; then
			echo $master
			break
		fi

		if [ "${master/*_FAILED/DONE}" = "DONE" ]; then
			echo $master
			break
		fi

		sleep 15
	done
}

################################
# add unit tests here
################################

################################
# black-box/functional tests, lambda returns JSON
################################
echo "expect trigger, fail to publish is ok"
(cd build; python3 s3-code.py ../test-input/event1.json)
# returns no files
(cd build; python3 s3-code.py ../test-input/ctevent1.json)
# returns multiple files
(cd build; python3 s3-code.py ../test-input/ctevents.json)

################################
# build
################################
(cd build; rm -rf __pycache__; zip ../demo.zip *.py clamdscan scan.conf)

################################
# upload artifacts
################################
aws s3 cp demo.zip s3://eft-distro-east-1/private4/Lambda/
aws s3 cp pyhelper.zip s3://eft-distro-east-1/private4/Lambda/
aws s3 cp s3-deploy.yaml s3://eft-distro-east-1/private4/s3-deploy.yaml

################################
# deploy
#
# replace: KeypairName, PublicSubnet, VpcId values with account-specific values
################################
stack=demo
distro=private4
aws cloudformation create-stack --stack-name $stack \
       --template-url https://eft-distro-east-1.s3.amazonaws.com/${distro}/s3-deploy.yaml \
       --disable-rollback \
       --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM CAPABILITY_NAMED_IAM \
       --parameters \
          ParameterKey=DistroPrefix,ParameterValue=${distro} \
          ParameterKey=NotificationEmail,ParameterValue=ADD-YOUR-EMAIL-HERE \
          ParameterKey=CreateServer,ParameterValue=false
#          ParameterKey=NotificationEmail,ParameterValue=steve.p.sonnenberg@gmail.com \
#          ParameterKey=CreateServer,ParameterValue=true \
#          ParameterKey=KeypairName,ParameterValue=2020 \
#          ParameterKey=PublicSubnet,ParameterValue=subnet-2e4a6949 \
#          ParameterKey=VpcId,ParameterValue=vpc-e12a559b 
# wait for complete
monitor $stack

################################
# manual tests (hard to integrate email)
################################
# upload real files to /Transfer, get an email, contains pre-signed url
# upload files to /, get none
# upload virus files get an email virus: "tainted" and no pre-signed url
# download files, expect delayed email results

################################
# tear down
################################
echo -n "Press <CR> to tear down the stack"
read answer
aws cloudformation delete-stack --stack-name $stack
# wait for complete
monitor $stack

