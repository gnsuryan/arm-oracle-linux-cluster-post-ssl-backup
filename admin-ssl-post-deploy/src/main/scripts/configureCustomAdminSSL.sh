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
  echo_stderr "./configureCustomAdminSSL.sh <adminVMName> <wlsDomainName> <wlsUserName> <wlsPassword> <oracleHome> <wlsDomainPath> <managedServerPrefix> <numberOfExistingNodes> <isCoherenceEnabled> <vmIndex> <enableAAD> <wlsADSSLCer> <isCustomSSLenabled> <customIdentityKeyStoreBase64String> <customIdentityKeyStorePassPhrase> <customIdentityKeyStoreType> <customTrustKeyStoreBase64String> <customTrustKeyStorePassPhrase> <customTrustKeyStoreType> <privateKeyAlias> <privateKeyPassPhrase>"
}

function installUtilities()
{
    echo "Installing zip unzip wget vnc-server rng-tools cifs-utils"
    sudo yum install -y zip unzip wget vnc-server rng-tools cifs-utils

    #Setting up rngd utils
    attempt=1
    while [[ $attempt -lt 4 ]]
    do
       echo "Starting rngd service attempt $attempt"
       sudo systemctl start rngd
       attempt=`expr $attempt + 1`
       sudo systemctl status rngd | grep running
       if [[ $? == 0 ]]; 
       then
          echo "rngd utility service started successfully"
          break
       fi
       sleep 1m
    done  
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
    echo "Cleanup completed."
}

#This function to add machine for a given managed server
function configureSSL()
{
    echo "Configuring SSL on Admin Server: $wlsServerName"
    cat <<EOF >$wlsDomainPath/configureSSL.py

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
arguments = '-Dweblogic.Name=$wlsServerName  -Dweblogic.security.SSL.ignoreHostnameVerification=true'
cmo.setArguments(arguments)

save()
resolve()
activate()
destroyEditSession("$wlsServerName")
disconnect()
EOF

sudo chown -R $username:$groupname $wlsDomainPath/configureSSL.py

echo "Running wlst script to configure SSL on $wlsServerName"
runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; java $WLST_ARGS weblogic.WLST $wlsDomainPath/configureSSL.py"
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
export CHECK_URL="http://$wlsAdminURL/weblogic/ready"
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

function restartAdminServerService()
{
     echo "Restart weblogic admin server service"
     sudo systemctl stop wls_admin
     sudo systemctl start wls_admin
}

function configureNodeManagerSSL()
{
 
    echo "configuring NodeManagerSSL at $wlsDomainPath/$wlsDomainName/nodemanager/nodemanager.properties"
 
    if [ "${isCustomSSLEnabled}" == "true" ];
    then
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
     echo "Restart NodeManager service"
     sudo systemctl stop wls_nodemanager
     sudo systemctl start wls_nodemanager
}

function restartManagedServer()
{
    echo "Restart managed server"
    cat <<EOF >${SCRIPT_PWD}/restart-managedServer.py
import os

connect('$wlsUserName','$wlsPassword','t3://$wlsAdminURL')
cd('/')
current_m=''
machines = cmo.getMachines()
for m in machines:
    hostname = os.environ['HOSTNAME']
    nm = m.getNodeManager()
    if nm.getListenAddress() in hostname:
        current_m=m

servers = cmo.getServers()
for s in servers:
    name = s.getName()
    if name != 'AdminServer':
        ref = getMBean('/Servers/'+name+'/Machine/'+current_m.getName())
        if ref != None:
            shutdown(name,'Server')
            start(name,'Server')

disconnect()
EOF
    . $oracleHome/oracle_common/common/bin/setWlstEnv.sh
    java $WLST_ARGS weblogic.WLST ${SCRIPT_PWD}/restart-managedServer.py 

    if [[ $? != 0 ]]; then
        echo "Error : Fail to restart managed server."
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

if [ $# -lt 9 ]
then
    usage
    exit 1
fi

export adminVMName=$1
export wlsDomainName=$2
export wlsUserName=$3
export wlsPassword=$4
export oracleHome=$5
export wlsDomainPath=$6

export managedServerPrefix="${7}"
export numberOfExistingNodes="${8}"

export isCoherenceEnabled="${9}"
isCoherenceEnabled="${isCoherenceEnabled,,}"

export vmIndex="${10}"

export managedServerName="$managedServerPrefix$vmIndex"

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
export wlsAdminChannelPort=7005
export wlsAdminURL="$adminVMName:$wlsAdminChannelPort"
export wlsServerName="admin"
export username="oracle"
export groupname="oracle"

export KEYSTORE_PATH="$wlsDomainPath/$wlsDomainName/keystores"

validateInput
cleanup

parseAndSaveCustomSSLKeyStoreData

#if vmIndex is 0, the script is running on admin server, else on managed server
if [ $vmIndex == 0 ];
then
    if [ "$enableAAD" == "true" ];then
        parseLDAPCertificate
        importAADCertificateIntoWLSCustomTrustKeyStore
    fi
    
    wait_for_admin
    configureSSL
    restartAdminServerService
    wait_for_admin
else
    wait_for_admin
    configureNodeManagerSSL
    restartNodeManagerService
    restartManagedServer
fi

cleanup