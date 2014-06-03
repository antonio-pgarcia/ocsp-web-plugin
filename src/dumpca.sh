#!/usr/bin/bash 

#--------------------------------------------------------------------------------
# @dumpca.sh script - dumps iplanet trusted ca certificate
# HolisticView - 2007
#--------------------------------------------------------------------------------

RM=/usr/bin/rm
AWK=/usr/bin/awk
GREP=/usr/bin/grep
UNAME=/usr/bin/uname 

#--------------------------------------------------------------------------------
# @USAGE
# 
# @param 
# @return
# @desc Shows the correct command line syntax
#--------------------------------------------------------------------------------
USAGE()
{
	echo "#----------------------------------------------------------------------"
	echo "# @dumpca.sh script - dumps iplanet trusted ca certificate"
	echo "# HolisticView - 2007"
	echo "#----------------------------------------------------------------------"
	echo
	echo "Missing command line parameter!"
	echo
	echo "${0} <iplanet base directory> <web server prefix>"
	echo
}

#--------------------------------------------------------------------------------
# @GET_SUNONE_INFO
# 
# @param $1: WEB SERVER BASE INSTALL DIRECTORY
# @param $2: WEB SERVER ID
# @return
# @desc Gather web server data
#--------------------------------------------------------------------------------
GET_SUNONE_INFO() 
{
	SUNONE_BASEDIR=$1
	SUNONE_SERVERID=$2
	
	SUNONE_PREFIX=${SUNONE_SERVERID}-$(${UNAME} -n)-
	SUNONE_CERTUTIL=${SUNONE_BASEDIR}/bin/https/admin/bin/certutil
	SUNONE_DATABASE=${SUNONE_BASEDIR}/alias
	SUNONE_LIBRARY=${SUNONE_BASEDIR}/bin/https/lib
	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${SUNONE_LIBRARY}
}

GET_TMP_FILENAME()
{
	TEMP_FILENAME=/tmp/${1}$$.tmp
}

DELETE_TMP_FILE()
{
	if [ -f ${TEMP_FILENAME} ]
	then
		${RM} ${TEMP_FILENAME}
	fi
}

#--------------------------------------------------------------------------------
# @GET_TRUSTED_CA
# 
# @param 
# @return
# @desc 
#--------------------------------------------------------------------------------
GET_TRUSTED_CA()
{
	${SUNONE_CERTUTIL} -L -d ${SUNONE_DATABASE} -P ${SUNONE_PREFIX} | ${GREP} "CT,," | ${AWK} '{printf "%s\n",substr($0,1, index($0,"CT,,") -1 )}' > ${TEMP_FILENAME}
}

GET_TRUSTED_CA_CERTS()
{
	while read CAID
	do
		${SUNONE_CERTUTIL} -L -d ${SUNONE_DATABASE} -P ${SUNONE_PREFIX} -n "${CAID}" -a -o "${CAID}".cer
	done < ${TEMP_FILENAME}
}

#--------------------------------------------------------------------------------
# MAIN PROC
# 
#--------------------------------------------------------------------------------

if [ $# -lt 2 ] 
then
	USAGE
	exit
fi

GET_TMP_FILENAME $0
GET_SUNONE_INFO $1 $2
GET_TRUSTED_CA
GET_TRUSTED_CA_CERTS
DELETE_TMP_FILE
