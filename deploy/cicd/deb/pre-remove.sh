
#!/bin/bash

set -e

################### Remove osctrl user and group ###################
if id -u osctrl &>/dev/null
then
    deluser --remove-home osctrl
fi
