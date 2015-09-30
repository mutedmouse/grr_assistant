#!/bin/bash
#############################################################
#   Created by: Andrew Quill                                #
#   Date: 30 September 2015                                 #
#############################################################
#   This script processes downloaded ExportedProcess.csv    #
#   and ExportedNetworkConnection.csv to build associated   #
#   Hostname, Application Name, Application Path, User      #
#   Execution Attrribution, Timestamp and Network State     #
#                                                           #
#   Once complete anomaloy detection may be done against    #
#   the results for isolation of suspicious processes and   #
#   connections.                                            #
#############################################################
#   Ensure you have already executed the ListProcess hunt   #
#   and have not enabled fetch binary option.               #
#############################################################
#   For formatting purposes execute the following command   #
#   ONE TIME ONLY against ExportedProcess.csv:              #
#   sed -i 's/\\/\\\\/g' ExportedProcess.csv                #
#############################################################
echo "Ensure execution location contains both ExportedNetworkConnection.csv and ExportedProcess.csv"
while read procs
do
   conns=$( grep "$( echo $proc | cut -f1 -d, )" ExportedNetworkConnection.csv \
   | grep ",$( echo -n $procs | cut -f16 -d, )," )
   
   echo "$( echo $procs | cut -f2,16,17,18,19,20,28 -d, ),$( echo $conns \
   | cut -f10,18,19,20,21,22 -d, )"
done < ExportedProcess.csv
