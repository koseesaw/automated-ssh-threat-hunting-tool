#!/usr/bin/env bash

audit_time=$(date)
host_name=$(hostname)
threshold=5
log_file_name="$1"
title() {
echo "================================================================="
echo "*****************************************************************"
echo "                  SSH THREAT HUNTING REPORT                      "
echo "================================================================="
}
service_check() {
ssh_status=$(systemctl is-active ssh)
     if [[ "$ssh_status" = "active" ]]
     then
         service_stat="ACTIVE"
     elif [[ "$ssh_status" = "inactive" ]]
     then
         service_stat="INACTIVE"
     else
         service_stat="STOPPED"
     fi
}
#Here we would check for failed login attempts,most suspicious ip,most attempted username then we would calculate total failed ip and attempts per ip.
analyzing_failed_ssh_authentication() { 
failed_login_attempts=$(grep -i "failed password" "$log_file_name" )
most_suspicious_ip=$(echo "$failed_login_attempts" | awk '{
            for(i=1;i<=NF;i++) {
              if($i=="from") {
                if($(i+1)=="invalid")
                  print $(i+2)
                else
                   print $(i+1)
              }
             }
            }' | sort | uniq -c | sort -rn | head -n 1)
read number_ip_tried_login top_sus_ip <<< "$most_suspicious_ip"
most_attempted_username=$(echo "$failed_login_attempts" | awk '{
            for(i=1;i<=NF;i++) {
              if($i=="for") {
                if($(i+1)=="invalid")
                  print $(i+2)
                else
                   print $(i+1)
              }
             }
            }' | sort | uniq -c | sort -rn | head -n 1)
read times_username_attempted top_username_attempted <<< "$most_attempted_username"

total_failed_login=$(echo "$failed_login_attempts" | grep -c "." )
attempts_per_ip=$(echo "$failed_login_attempts" | awk '{
            for(i=1;i<=NF;i++) {
              if($i=="from") {
                if($(i+1)=="invalid")
                  print $(i+2)
                else
                   print $(i+1)
              }
             }
            }' | sort | uniq -c | sort -rn)
}
identifying_most_targeted_usernames() {
targeted_usernames=$(echo "$failed_login_attempts" | awk '{
            for(i=1;i<=NF;i++) {
              if($i=="for") {
                if($(i+1)=="invalid")
                  print $(i+2)
                else
                   print $(i+1)
              }
             }
            }' | sort | uniq -c | sort -rn)
}
detecting_suspicious_ips() {
while read attempts ips
do
      if [[ "$attempts" -ge "$threshold" ]]
      then
            risk_level="HIGH"
            risk_level_tip="Investigate Logs Immediately"
     else
           risk_level="LOW"
           risk_level_tip="Continuously Monitor Logs"
     fi
done <<< "$attempts_per_ip"
}
checking_successful_logins() {
successful_login=$(grep -i "accepted password" "$log_file_name" )
count_successful_logins=$(echo "$successful_login" | grep -c ".")
}
overall_risk_analysis() {
if [[ "$total_failed_login" -ge "$threshold" ]]
then
    while read attempts ips
    do
       if [[ "$attempts" -ge "$threshold" ]]
       then
           overall_risk="CRITICAL"
           overall_risk_tip="Investigate IPs and Logs Immediately"
       fi
    done <<< "$attempts_per_ip"
else
     overall_risk="NORMAL"
     overall_risk_tip="Monitor Logs Continuously"
fi

}
generating_report() {
echo
title
echo "Audit Date And Time : $audit_time"
echo "Hostname : $host_name"
echo "SSH Status : $service_stat"
echo
echo "FAILED AUTHENTICATION"
echo "----------------------"
echo "Total Failed Attempts : $total_failed_login"
echo
echo "TOP SOURCE IP"
echo "=============="
echo "Top Suspicious IP : $top_sus_ip"
echo "Number Of Login Attempt : $number_ip_tried_login"
echo
echo "TOP TARGETED USERNAME"
echo "======================"
echo "Top Targeted Username : $top_username_attempted"
echo "Number Of Attempts : $times_username_attempted"
echo
echo "SUCCESSFUL AUTHENTICATION"
echo "-------------------------"
echo "Total Successful Logins : $count_successful_logins"
echo
echo "SUSPICIOUS IPs"
echo "=============="
echo "Risk Level Suspicious IPs : $risk_level"
echo "Recommendation : $risk_level_tip"
echo
echo "OVERALL RISK ANALYSIS"
echo "====================="
echo "Overall Risk : $overall_risk"
echo "Recommendation : $overall_risk_tip"
echo
echo "======================================================================"
}

full_investigation() {
if [[ -f "$log_file_name" ]] && [[ -r "$log_file_name" ]]
then
         service_check
         analyzing_failed_ssh_authentication
         identifying_most_targeted_usernames
         detecting_suspicious_ips
         checking_successful_logins
         overall_risk_analysis
         generating_report

else
      echo "File Does Not Exist Or Is Not Readable"
fi
}
full_investigation
