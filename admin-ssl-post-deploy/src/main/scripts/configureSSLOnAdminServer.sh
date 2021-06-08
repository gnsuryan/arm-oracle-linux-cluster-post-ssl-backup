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
arguments = '-Dweblogic.Name=$wlsServerName  -Dweblogic.security.SSL.ignoreHostnameVerification=true'
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


#This function to wait for managed/coherence server to start
function wait_for_server()
{
count=1
export CHECK_URL="$1"
export serverName="$2"
echo "verifying if $serverName is available by verifying URL: $CHECK_URL"
status=`curl --insecure -ILs $CHECK_URL | tac | grep -m1 HTTP/1.1 | awk {'print $2'}`
echo "Waiting for managed server $serverName to start"

if [ "$status" == "200" ];
then
    echo "Server $serverName started succesfully..."
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
    i=1
    while [ $i -le $numberOfExistingNodes ]
    do
      managedServerVMName="${managedServerPrefix}VM${i}"
      serverName="${managedServerPrefix}${i}"
      readyURL=http://$managedServerVMName:$wlsManagedServerPort/weblogic/ready
      wait_for_server $readyURL $serverName
      (( i++ ))
    done
    
    echo "All Managed Servers started successfully"   
}

function validate_coherence_servers()
{
    i=1
    while [ $i -le $numberOfCoherenceCacheInstances ]
    do
      coherenceServerVMName="${coherenceServerPrefix}VM${i}"
      serverName="${coherenceServerPrefix}${i}"
      readyURL=http://$managedServerVMName:$wlsCoherenceServerPort/weblogic/ready
      wait_for_server $readyURL $serverName
      (( i++ ))
    done
    
    echo "All Coherence Servers started successfully"   
}

# restart domain using rolling restart
function restart_domain_with_rolling_restart() 
{

echo "Restarting Domain using Rolling Restart WLST function"
cat <<EOF >${SCRIPT_PATH}/rolling_restart.py

connect('$wlsUserName','$wlsPassword','t3://$wlsAdminURL')
progress = rollingRestart('$wlsDomainName')
disconnect()
progress.getProgressString()
EOF

sudo chown -R $username:$groupname ${SCRIPT_PATH}/rolling_restart.py

echo "Running wlst script to kickoff rolling restart for Domain $$wlsDomainName"
runuser -l oracle -c ". $oracleHome/oracle_common/common/bin/setWlstEnv.sh; java $WLST_ARGS weblogic.WLST ${SCRIPT_PATH}/rolling_restart.py"
if [[ $? != 0 ]]; then
     echo "Error : Rolling Restart failed"
     exit 1
fi
  
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
export numberOfExistingNodes="${8}"

export isCoherenceEnabled="${9}"
isCoherenceEnabled="${isCoherenceEnabled,,}"

export numberOfCoherenceCacheInstances="${10}"

export vmIndex="${11}"

if [ $vmIndex == 0 ];
then
    wlsServerName="admin"
fi

echo "ServerName: $wlsServerName"

export enableAAD="${12}"
enableAAD="${enableAAD,,}"

export wlsADSSLCer="${13}"

export isCustomSSLEnabled="${14}"
isCustomSSLEnabled="${isCustomSSLEnabled,,}"

if [ "${isCustomSSLEnabled,,}" == "true" ];
then
    export customIdentityKeyStoreBase64String="${15}"
    export customIdentityKeyStorePassPhrase="${16}"
    export customIdentityKeyStoreType="${17}"
    export customTrustKeyStoreBase64String="${18}"
    export customTrustKeyStorePassPhrase="${19}"
    export customTrustKeyStoreType="${20}"
    export privateKeyAlias="${21}"
    export privateKeyPassPhrase="${22}"
fi

export wlsAdminPort=7001
export wlsAdminSSLPort=7002
export wlsAdminChannelPort=7005
export wlsManagedServerPort=8001
export wlsCoherenceServerPort=7501
export wlsAdminURL="$adminVMName:$wlsAdminChannelPort"

export username="oracle"
export groupname="oracle"
export restartAttempt=0

export KEYSTORE_PATH="$wlsDomainPath/$wlsDomainName/keystores"
export SCRIPT_PATH="/u01/app/scripts"

mkdir -p ${SCRIPT_PATH}
sudo chown -R ${username}:${groupname} ${SCRIPT_PATH}


#if vmIndex is 0, the script is running on admin server, else on managed server
if [ $vmIndex == 0 ];
then
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
    restart_domain_with_rolling_restart
    wait_for_admin
    validate_managed_servers

    if [ "$isCoherenceEnabled" == "true" ]; 
    then
        validate_coherence_servers
    fi
    
    cleanup
else
    #wait for 5 minutes so that admin server would have got configured with SSL and started.
    echo "This script is used only for configuring custom SSL on WebLogic Administration Server, post deployment"
    
fi


