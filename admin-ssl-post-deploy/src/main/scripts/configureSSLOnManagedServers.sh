#!/bin/bash

#Function to output message to StdErr
function echo_stderr ()
{
    echo "$@" >&2
    exit 1
}

#Function to display usage message
function usage()
{
  echo_stderr "./configureSSLOnManagedServers.sh <adminVMName> <wlsDomainName> <wlsUserName> <wlsPassword> <oracleHome> <wlsDomainPath> <managedServerVMName> <managedServerPrefix> <numberOfExistingNodes> <vmIndex> <isCustomSSLenabled> <customIdentityKeyStoreBase64String> <customIdentityKeyStorePassPhrase> <customIdentityKeyStoreType> <customTrustKeyStoreBase64String> <customTrustKeyStorePassPhrase> <customTrustKeyStoreType> <privateKeyAlias> <privateKeyPassPhrase>"
}

function validateInput()
{
    if [ -z "$adminVMName" ];
    then
        echo_stderr "adminVMName is required. "
    fi

    if [ -z "$wlsDomainName" ];
    then
        echo_stderr "wlsDomainName is required. "
    fi

    if [[ -z "$wlsUserName" || -z "$wlsPassword" ]]
    then
        echo_stderr "wlsUserName or wlsPassword is required. "
    fi

    if [ -z "$oracleHome" ];
    then
        echo_stderr "oracleHome is required. "
    fi

    if [ -z "$wlsDomainPath" ];
    then
        echo_stderr "wlsDomainPath is required. "
    fi

    if [[ -z "$managedServerVMName" ]];
    then
        echo_stderr "managedServerVMName is required. "
    fi

    if [[ -z "$managedServerPrefix" ]];
    then
        echo_stderr "managedServerPrefix is required. "
    fi

    if [[ -z "$numberOfExistingNodes" ]];
    then
        echo_stderr "numberOfExistingNodes is required. "
    fi

    if [ "$isCustomSSLEnabled" == "true" ];
    then
        if [[ -z "$customIdentityKeyStoreBase64String" || -z "$customIdentityKeyStorePassPhrase"  || -z "$customIdentityKeyStoreType" ||
              -z "$customTrustKeyStoreBase64String" || -z "$customTrustKeyStorePassPhrase"  || -z "$customTrustKeyStoreType" ||
              -z "$privateKeyAlias" || -z "$privateKeyPassPhrase" ]]
        then
            echo_stderr "customIdentityKeyStoreBase64String, customIdentityKeyStorePassPhrase, customIdentityKeyStoreType, customTrustKeyStoreBase64String, customTrustKeyStorePassPhrase, customTrustKeyStoreType, privateKeyAlias and privateKeyPassPhrase are required. "
            exit 1
        fi
    else
        echo "SSL configuration not enabled as iscustomSSLEnabled was set to false. Please set the flag to true and retry."
        exit 1
    fi
}

#Function to cleanup all temporary files
function cleanup()
{
    echo "Cleaning up temporary files..."
    rm -rf $wlsDomainPath/managed-domain.yaml
    rm -rf $wlsDomainPath/weblogic-deploy.zip
    rm -rf $wlsDomainPath/weblogic-deploy
    rm -rf $wlsDomainPath/*.py
    rm -rf ${SCRIPT_PATH}/*
    echo "Cleanup completed."
}

#configure SSL
function configureSSL()
{
    echo "Configuring SSL on Server: $wlsServerName"
    cat <<EOF >${SCRIPT_PATH}/configureSSL.py

isCustomSSLEnabled='${isCustomSSLEnabled}'

connect('$wlsUserName','$wlsPassword','t3://$wlsAdminURL')
edit("$wlsServerName")
startEdit()
cd('/Servers/$wlsServerName')

if isCustomSSLEnabled == 'true' :
    cmo.setKeyStores('CustomIdentityAndCustomTrust')
    cmo.setCustomIdentityKeyStoreFileName('$customSSLIdentityKeyStoreFile')
    cmo.setCustomIdentityKeyStoreType('$customIdentityKeyStoreType')
    set('CustomIdentityKeyStorePassPhrase', '$customIdentityKeyStorePassPhrase')
    cmo.setCustomTrustKeyStoreFileName('$customSSLTrustKeyStoreFile')
    cmo.setCustomTrustKeyStoreType('$customTrustKeyStoreType')
    set('CustomTrustKeyStorePassPhrase', '$customTrustKeyStorePassPhrase')

    cd('/Servers/$wlsServerName/SSL/$wlsServerName')
    cmo.setServerPrivateKeyAlias('$privateKeyAlias')
    set('ServerPrivateKeyPassPhrase', '$privateKeyPassPhrase')
    cmo.setHostnameVerificationIgnored(true)

cd('/Servers/$wlsServerName/ServerStart/$wlsServerName')
arguments = '-Dweblogic.Name=$wlsServerName  -Dweblogic.security.SSL.ignoreHostnameVerification=true -Dweblogic.management.server=http://$wlsAdminURL ${wlsCoherenceArgs}'
cmo.setArguments(arguments)

save()
resolve()
activate()
destroyEditSession("$wlsServerName")
disconnect()
EOF

sudo chown -R $username:$groupname ${SCRIPT_PATH}/configureSSL.py

echo "Running wlst script to configure SSL on $wlsServerName"
runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; java $WLST_ARGS weblogic.WLST ${SCRIPT_PATH}/configureSSL.py"
if [[ $? != 0 ]]; then
     echo "Error : SSL Configuration for server $wlsServerName failed"
     exit 1
fi

}

#This function to wait for admin server
function wait_for_admin()
{
 #wait for admin to start
count=1
export CHECK_URL="http://$adminVMName:$wlsAdminChannelPort/weblogic/ready"
status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
echo "Waiting for admin server to start"
while [[ "$status" != "200" ]]
do
  echo "."
  count=$((count+1))
  if [ $count -le 30 ];
  then
      sleep 1m
  else
     echo "Error : Maximum attempts exceeded while starting admin server"
     exit 1
  fi
  status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
  if [ "$status" == "200" ];
  then
     echo "Server $wlsServerName started succesfully..."
     break
  fi
done
}


#This function to wait for managed server
function wait_for_managed_server()
{
count=1
export CHECK_URL="http://$managedServerVMName:$wlsManagedServerPort/weblogic/ready"
status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
echo "Waiting for managed server $wlsServerName to start"

if [ "$status" == "200" ];
then
    echo "Server $wlsServerName started succesfully..."
    break
else
    while [[ "$status" != "200" ]]
    do
      echo "."
      count=$((count+1))
      if [ $count -le 10 ];
      then
          sleep 1m
      else
            echo "Failed to reach server $wlsServerName even after maximum attemps"
            exit 1
      fi
      status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
      if [ "$status" == "200" ];
      then
         echo "Server $wlsServerName started succesfully..."
         break
      fi
    done
fi
}


function validateSSLKeyStores()
{
   sudo chown -R $username:$groupname $KEYSTORE_PATH

   #validate identity keystore
   runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; keytool -list -v -keystore $customSSLIdentityKeyStoreFile -storepass $customIdentityKeyStorePassPhrase -storetype $customIdentityKeyStoreType | grep 'Entry type:' | grep 'PrivateKeyEntry'"

   if [[ $? != 0 ]]; then
       echo "Error : Identity Keystore Validation Failed !!"
       exit 1
   fi

   #validate Trust keystore
   runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; keytool -list -v -keystore $customSSLTrustKeyStoreFile -storepass $customTrustKeyStorePassPhrase -storetype $customTrustKeyStoreType | grep 'Entry type:' | grep 'trustedCertEntry'"

   if [[ $? != 0 ]]; then
       echo "Error : Trust Keystore Validation Failed !!"
       exit 1
   fi

   echo "ValidateSSLKeyStores Successfull !!"
}

function parseAndSaveCustomSSLKeyStoreData()
{
    echo "create key stores for custom ssl settings"

    mkdir -p ${KEYSTORE_PATH}
    touch ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt

    echo "$customIdentityKeyStoreBase64String" > ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt
    cat ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt | base64 -d > ${KEYSTORE_PATH}/identity.keystore
    export customSSLIdentityKeyStoreFile=${KEYSTORE_PATH}/identity.keystore

    rm -rf ${KEYSTORE_PATH}/identityKeyStoreCerBase64String.txt

    mkdir -p ${KEYSTORE_PATH}
    touch ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt

    echo "$customTrustKeyStoreBase64String" > ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt
    cat ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt | base64 -d > ${KEYSTORE_PATH}/trust.keystore
    export customSSLTrustKeyStoreFile=${KEYSTORE_PATH}/trust.keystore

    rm -rf ${KEYSTORE_PATH}/trustKeyStoreCerBase64String.txt

    validateSSLKeyStores
}

function configureNodeManagerSSL()
{

    echo "configuring NodeManagerSSL at $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties"

    if [ "${isCustomSSLEnabled}" == "true" ];
    then

        sed -i '/KeyStores=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomIdentityKeystoreType=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomIdentityKeyStoreFileName=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomIdentityKeyStorePassPhrase=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomIdentityAlias=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomIdentityPrivateKeyPassPhrase=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomTrustKeystoreType=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomTrustKeyStoreFileName=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        sed -i '/CustomTrustKeyStorePassPhrase=/d' $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties

        echo "KeyStores=CustomIdentityAndCustomTrust" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomIdentityKeystoreType=${customIdentityKeyStoreType}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomIdentityKeyStoreFileName=${customSSLIdentityKeyStoreFile}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomIdentityKeyStorePassPhrase=${customIdentityKeyStorePassPhrase}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomIdentityAlias=${privateKeyAlias}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomIdentityPrivateKeyPassPhrase=${privateKeyPassPhrase}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomTrustKeystoreType=${customTrustKeyStoreType}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomTrustKeyStoreFileName=${customSSLTrustKeyStoreFile}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
        echo "CustomTrustKeyStorePassPhrase=${customTrustKeyStorePassPhrase}" >> $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties
    fi
}

function restartNodeManagerService()
{
     echo "Restart NodeManager - first killing nodemanager process so that it gets restarted by the nodemanager service automatically"

     echo "listing nodemanager process before restart"
     ps -ef|grep 'weblogic.NodeManager'|grep -i 'weblogic.nodemanager.JavaHome'

     #kill nodemanager process if not already stopped by nodemanager service
     ps -ef|grep 'weblogic.NodeManager'|awk '{ print $2; }'|head -n 1 | xargs kill -9

     sleep 1m
     echo "listing nodemanager process"
     ps -ef|grep 'weblogic.NodeManager'|grep -i 'weblogic.nodemanager.JavaHome'
     if [ "$?" == "0" ];
     then
       echo "NodeManager re-started successfully"
     else
       echo "Failed to restart NodeManager"
       exit 1
     fi
}

#main script starts here

export SCRIPT_PWD=`pwd`

# store arguments in a special array
args=("$@")
# get number of elements
ELEMENTS=${#args[@]}

# echo each element in array
# for loop
for (( i=0;i<$ELEMENTS;i++)); do
    echo "ARG[${args[${i}]}]"
done

if [ $# -lt 15 ]
then
    usage
    exit 1
fi
export wlsServerName="admin"

export adminVMName=$1
export wlsDomainName=$2
export wlsUserName=$3
export wlsPassword=$4
export oracleHome=$5
export wlsDomainPath=$6

export managedServerVMName="${7}"

export managedServerPrefix=${8}

export numberOfExistingNodes="${9}"

export vmIndex="${10}"

if [ $vmIndex == 0 ];
then
    wlsServerName="admin"
else
    wlsServerName="$managedServerPrefix$vmIndex"
fi

echo "ServerName: $wlsServerName"

export isCustomSSLEnabled="${11}"
isCustomSSLEnabled="${isCustomSSLEnabled,,}"

if [ "${isCustomSSLEnabled,,}" == "true" ];
then
    export customIdentityKeyStoreBase64String="${12}"
    export customIdentityKeyStorePassPhrase="${13}"
    export customIdentityKeyStoreType="${14}"
    export customTrustKeyStoreBase64String="${15}"
    export customTrustKeyStorePassPhrase="${16}"
    export customTrustKeyStoreType="${17}"
    export privateKeyAlias="${18}"
    export privateKeyPassPhrase="${19}"
fi

export wlsAdminPort=7001
export wlsAdminSSLPort=7002
export wlsAdminChannelPort=7005
export wlsManagedServerPort=8001
export wlsAdminURL="$adminVMName:$wlsAdminChannelPort"

export coherenceLocalport=42000
export coherenceLocalportAdjust=42200
export coherenceDebugSettings="-Djavax.net.debug=ssl,handshake -Dcoherence.log.level=9"
export wlsCoherenceArgs="-Dcoherence.localport=$coherenceLocalport -Dcoherence.localport.adjust=$coherenceLocalportAdjust"

export username="oracle"
export groupname="oracle"
export restartAttempt=0

export KEYSTORE_PATH="$wlsDomainPath/$wlsDomainName/keystores"
export SCRIPT_PATH="/u01/app/scripts"

mkdir -p ${SCRIPT_PATH}
sudo chown -R ${username}:${groupname} ${SCRIPT_PATH}

validateInput
cleanup
parseAndSaveCustomSSLKeyStoreData
wait_for_admin
configureSSL
configureNodeManagerSSL
restartNodeManagerService
cleanup