Goals:

Demonstrates a notification of file upload to a designated bucket/prefix (e.g. /Transfer)
Demonstrates a notification on the object download from a designated bucket
Implemented a virus scanner (as an EC2)
Installs in any account using a CloudFormation
Includes a self-contained test capabilities

Deliverable:

Lambda – build/s3-code.py, build/utils.py
Lambda – cfnhelper.zip
CFT Template – s3-deploy.yaml
Driver Script – demo.sh

Demo Driver script
The driver script consists of the following operations:
1.	Unit tests – placeholder
   a.	Use pytest (etc.) to validate specific function behavior (not terribly interesting)
2.	Functional tests
   a.	Run the lambda code as a standalone utility and verify its behavior passing it simulated events. It won’t have virus scanning, but the rest of the logic can be tested. In this mode, it will return the json as stdout (in lieu of sending notifications)
   b.	There are several events supplied in the test-input folder than can be fed one at a time or in bulk to the lambda
3.	Build artifacts
   a.	Creates the lambda and uploads artifacts to the deploy bucket s3://eft-distro-east-1/
4.	Deploy using CFT
   a.	The script drives cloudformation
5.	Mail subscription configuration, Actual Testing
6.	Teardown 

Note: you need to update the Parameters in demo.sh before running (see ParameterValue)
