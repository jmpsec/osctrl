#!/bin/sh
# ASCII art generated in http://patorjk.com/software/taag with font ANSI Shadow
printf "                                                           \n"
printf "   ██████╗  ███████╗  ██████╗ ████████╗ ██████╗  ██╗       \n"
printf "  ██╔═══██╗ ██╔════╝ ██╔════╝ ╚══██╔══╝ ██╔══██╗ ██║       \n"
printf "  ██║   ██║ ███████╗ ██║         ██║    ██████╔╝ ██║       \n"
printf "  ██║   ██║ ╚════██║ ██║         ██║    ██╔══██╗ ██║       \n"
printf "  ╚██████╔╝ ███████║ ╚██████╗    ██║    ██║  ██║ ███████╗  \n"
printf "   ╚═════╝  ╚══════╝  ╚═════╝    ╚═╝    ╚═╝  ╚═╝ ╚══════╝  \n"
printf "                                                           \n"


#System date
date=`date`
 
#System load
LOAD1=`cat /proc/loadavg | awk {'print $1'}`
LOAD5=`cat /proc/loadavg | awk {'print $2'}`
LOAD15=`cat /proc/loadavg | awk {'print $3'}`
 
#System uptime
uptime=`cat /proc/uptime | cut -f1 -d.`
upDays=$((uptime/60/60/24))
upHours=$((uptime/60/60%24))
upMins=$((uptime/60%60))
upSecs=$((uptime%60))
 
#Root fs info
root_usage=`df -h / | awk '/\// {print $4}'|grep -v "^$"`
 
#Memory Usage
memory_usage=`free -m | awk '/Mem:/ { total=$2 } /buffers\/cache/ { used=$3 } END { printf("%3.1f%%", used/total*100)}'`
 
#Interfaces
INTERFACE=$(ip -4 ad | grep 'state UP' | awk -F ":" '!/^[0-9]*: ?lo/ {print $2}')
 
echo "System information as of: $date"
echo
printf "System Load:\t%s %s %s\tSystem Uptime:\t%s "days" %s "hours" %s "min" %s "sec"\n" $LOAD1, $LOAD5, $LOAD15 $upDays $upHours $upMins $upSecs
printf "Memory Usage:\t%s\t\t\tDisk Usage:\t%s\n" $memory_usage $root_usage
printf "\n"
printf "Interface\tMAC Address\t\tIP Address\t\n"
 
for x in $INTERFACE
do
  MAC=$(ip ad show dev $x |grep link/ether |awk '{print $2}')
  IP=$(ip ad show dev $x |grep -v inet6 | grep inet|awk '{print $2}')
  printf  $x"\t\t"$MAC"\t"$IP"\t\n"
done

echo
