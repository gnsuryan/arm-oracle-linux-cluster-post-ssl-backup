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
  echo_stderr "./configureCustomAdminSSL.sh <adminVMName> <wlsDomainName> <wlsUserName> <wlsPassword> <oracleHome> <wlsDomainPath> <managedServerPrefix> <numberOfExistingNodes> <isCoherenceEnabled> <numberOfCoherenceCacheInstances> <vmIndex> <enableAAD> <wlsADSSLCer> <isCustomSSLenabled> <customIdentityKeyStoreBase64String> <customIdentityKeyStorePassPhrase> <customIdentityKeyStoreType> <customTrustKeyStoreBase64String> <customTrustKeyStorePassPhrase> <customTrustKeyStoreType> <privateKeyAlias> <privateKeyPassPhrase>"
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

    if [[ "$enableAAD" == "true" ]];
    then
        if [[ -z "$wlsADSSLCer" ]]
        then
            echo_stderr "wlsADSSLCer is required. "
        fi
    fi

    if [[ -z "$managedServerPrefix" ]];
    then
        echo_stderr "managedServerPrefix is required. "
    fi

    if [[ -z "$numberOfExistingNodes" ]];
    then
        echo_stderr "numberOfExistingNodes is required. "
    fi

    if [[ -z "$isCoherenceEnabled" ]];
    then
        echo_stderr "wlsADSSLCer is required. "
    fi

        if [[ -z "$numberOfCoherenceCacheInstances" ]];
    then
        echo_stderr "numberOfCoherenceCacheInstances is required. "
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
arguments = '-Dweblogic.Name=$wlsServerName  -Dweblogic.security.SSL.ignoreHostnameVerification=true -Djavax.net.debug=ssl,handshake -Dcoherence.log.level=9'
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
echo "Waiting for admin server to start"
 #wait for admin to start
count=1
export CHECK_URL="http://$adminVMName:$wlsAdminChannelPort/weblogic/ready"
status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`

if [ "$status" == "200" ];
then
    echo "Server admin started succesfully..."
    return
else
    while [[ "$status" != "200" ]]
    do
      echo "admin server still not reachable at $CHECK_URL .. $count"
      count=$((count+1))
      if [ $count -le 10 ];
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
fi
}


#This function to wait for managed/coherence server to start
function wait_for_server()
{
echo "Waiting for managed server $serverName to start"
count=1
export CHECK_URL="$1"
export serverName="$2"
echo "verifying if $serverName is available by verifying URL: $CHECK_URL"
status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`

if [ "$status" == "200" ];
then
    echo "Server $serverName started succesfully..."
    return
else
    while [[ "$status" != "200" ]]
    do
      echo "managed/coherence server: $serverName - still not reachable at $CHECK_URL .. $count"
      count=$((count+1))
      if [ $count -le 10 ];
      then
          sleep 2m
      else
            echo "Failed to reach server $serverName even after maximum attempts"
            exit 1
      fi
      status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
      if [ "$status" == "200" ];
      then
         echo "Server $serverName started succesfully..."
         break
      fi
    done
fi
}

function validate_managed_servers()
{
    echo "validate managed servers: $numberOfExistingNodes"
    i=1
    while [[ $i -le $numberOfExistingNodes ]]
    do
      managedServerVMName="${managedServerPrefix}VM${i}"
      serverName="${managedServerPrefix}${i}"
      readyURL="http://$managedServerVMName:$wlsManagedServerPort/weblogic/ready"
      wait_for_server $readyURL $serverName
      i=$((i+1))
    done

    echo "All Managed Servers started successfully"
}

function validate_coherence_servers()
{
    echo "validate coherence servers: $numberOfCoherenceCacheInstances"
    j=1
    while [[ $j -le $numberOfCoherenceCacheInstances ]]
    do
      coherenceServerVMName="${coherenceServerPrefix}VM${j}"
      serverName="${coherenceServerPrefix}${j}"
      readyURL=http://$coherenceServerVMName:$wlsCoherenceServerPort/weblogic/ready
      wait_for_server $readyURL $serverName
      j=$((j+1))
    done

    echo "All Coherence Servers started successfully"
}

# restart servers using rolling restart
function restart_domain_with_rolling_restart()
{

target="$1"
echo "Restart cluster $target using Rolling Restart WLST function"
cat <<EOF >${SCRIPT_PATH}/rolling_restart_$target.py

import sys, socket
import os
import time
from java.util import Date
from java.text import SimpleDateFormat

### MAIN
argTarget='$target'

try:
   connect('$wlsUserName','$wlsPassword','t3://$wlsAdminURL')
   progress = rollingRestart(argTarget, options='isDryRun=false,shutdownTimeout=30,isAutoRevertOnFailure=true')
   lastProgressString = ""

   progressString=progress.getProgressString()
   steps=progressString.split('/')

   while not (steps[0].strip() == steps[1].strip()):
     if not (progressString == lastProgressString):
       print "Completed step " + steps[0].strip() + " of " + steps[1].strip() + " total steps"
       lastProgressString = progressString

     java.lang.Thread.sleep(1000)

     progressString=progress.getProgressString()
     steps=progressString.split('/')
     if(len(steps) == 1):
       print steps[0]
       break;

   if(len(steps) == 2):
     print "Completed step " + steps[0].strip() + " of " + steps[1].strip() + " total steps"

   t = Date()
   endTime=SimpleDateFormat("hh:mm:ss").format(t)

   print ""
   print "RolloutDirectory task finished at " + endTime
   print ""
   viewMBean(progress)

   state = progress.getStatus()
   error = progress.getError()
   #TODO: better error handling with the progress.getError obj and msg
   # not a string, can raise directly
   stateString = '%s' % state
   if stateString != 'SUCCESS':
     #msg = 'State is %s and error is: %s' % (state,error)
     msg = "State is: " + state
     raise(msg)
   elif error is not None:
     msg = "Error not null for state: " + state
     print msg
     #raise("Error not null for state: %s and error is: %s" + (state,error))
     raise(error)
except Exception, e:
  e.printStackTrace()
  dumpStack()
  raise("Rollout failed")

exit()

EOF

sudo chown -R $username:$groupname ${SCRIPT_PATH}/rolling_restart_$target.py

echo "Running wlst script to kickoff rolling restart for Domain $wlsDomainName"
runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; java $WLST_ARGS weblogic.WLST ${SCRIPT_PATH}/rolling_restart_$target.py"
if [[ $? != 0 ]]; then
     echo "Error : Rolling Restart failed"
     exit 1
fi

}

function force_restart_admin()
{
     echo "Force Restart AdminServer - first killing admin server process so that it gets restarted by the wls_admin service automatically"

     echo "listing admin server process before restart"
     ps -ef|grep 'weblogic.Server'|grep -i 'weblogic.Name=admin'

     ps -ef|grep 'weblogic.Server'|grep 'weblogic.Name=admin' |awk '{ print $2; }'|head -n 1 | xargs kill -9
     sleep 5m

     echo "listing admin server process after restart"
     ps -ef|grep 'weblogic.Server'|grep -i 'weblogic.Name=admin'
     wait_for_admin
}

function parseLDAPCertificate()
{
    echo "create key store"
    cer_begin=0
    cer_size=${#wlsADSSLCer}
    cer_line_len=64
    mkdir ${SCRIPT_PWD}/security
    touch ${SCRIPT_PWD}/security/AzureADLDAPCerBase64String.txt
    while [ ${cer_begin} -lt ${cer_size} ]
    do
        cer_sub=${wlsADSSLCer:$cer_begin:$cer_line_len}
        echo ${cer_sub} >> ${SCRIPT_PWD}/security/AzureADLDAPCerBase64String.txt
        cer_begin=$((cer_begin+$cer_line_len))
    done

    openssl base64 -d -in ${SCRIPT_PWD}/security/AzureADLDAPCerBase64String.txt -out ${SCRIPT_PWD}/security/AzureADTrust.cer
    export addsCertificate=${SCRIPT_PWD}/security/AzureADTrust.cer
}

function importAADCertificateIntoWLSCustomTrustKeyStore()
{
    if [ "${isCustomSSLEnabled,,}" == "true" ];
    then
        # set java home
        . $oracleHome/oracle_common/common/bin/setWlstEnv.sh

        #validate Trust keystore
        runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; keytool -list -v -keystore $customSSLTrustKeyStoreFile -storepass $customTrustKeyStorePassPhrase -storetype $customTrustKeyStoreType | grep 'Entry type:' | grep 'trustedCertEntry'"

        if [[ $? != 0 ]]; then
            echo "Error : Trust Keystore Validation Failed !!"
            exit 1
        fi

        # For SSL enabled causes AAD failure #225
        # ISSUE: https://github.com/wls-eng/arm-oraclelinux-wls/issues/225

        echo "Importing AAD Certificate into WLS Custom Trust Key Store: "

        sudo ${JAVA_HOME}/bin/keytool -noprompt -import -trustcacerts -keystore $customSSLTrustKeyStoreFile -storepass $customTrustKeyStorePassPhrase -alias aadtrust -file ${addsCertificate} -storetype $customTrustKeyStoreType
    else
        echo "customSSL not enabled. Not required to configure AAD for WebLogic Custom SSL"
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

export managedServerPrefix=${7}
export coherenceServerPrefix="${managedServerPrefix}Storage"
export numberOfExistingNodes="${8}"

export isCoherenceEnabled="${9}"
isCoherenceEnabled="${isCoherenceEnabled,,}"

export numberOfCoherenceCacheInstances="${10}"

export wlsServerName="admin"

echo "ServerName: $wlsServerName"

export enableAAD="${11}"
enableAAD="${enableAAD,,}"

export wlsADSSLCer="${12}"

export isCustomSSLEnabled="${13}"
isCustomSSLEnabled="${isCustomSSLEnabled,,}"

if [ "${isCustomSSLEnabled,,}" == "true" ];
then
    export customIdentityKeyStoreBase64String="${14}"
    export customIdentityKeyStorePassPhrase="${15}"
    export customIdentityKeyStoreType="${16}"
    export customTrustKeyStoreBase64String="${17}"
    export customTrustKeyStorePassPhrase="${18}"
    export customTrustKeyStoreType="${19}"
    export privateKeyAlias="${20}"
    export privateKeyPassPhrase="${21}"
fi

export wlsAdminPort=7001
export wlsAdminSSLPort=7002
export wlsAdminChannelPort=7005
export wlsManagedServerPort=8001
export wlsCoherenceServerPort=7501
export wlsAdminURL="$adminVMName:$wlsAdminChannelPort"

export username="oracle"
export groupname="oracle"

export clusterName="cluster1"
export coherenceClusterName="storage1"

export KEYSTORE_PATH="$wlsDomainPath/$wlsDomainName/keystores"
export SCRIPT_PATH="/u01/app/scripts"

mkdir -p ${SCRIPT_PATH}
sudo chown -R ${username}:${groupname} ${SCRIPT_PATH}


validateInput
cleanup
parseAndSaveCustomSSLKeyStoreData

if [ "$enableAAD" == "true" ];
then
    parseLDAPCertificate
    importAADCertificateIntoWLSCustomTrustKeyStore
fi

wait_for_admin
configureSSL

force_restart_admin

if [ "$isCoherenceEnabled" == "true" ];
then
    restart_domain_with_rolling_restart $coherenceClusterName
fi

restart_domain_with_rolling_restart $clusterName

wait_for_admin
validate_managed_servers

if [ "$isCoherenceEnabled" == "true" ];
then
    validate_coherence_servers
fi

cleanup
