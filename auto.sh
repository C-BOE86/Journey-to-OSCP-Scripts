#!/bin/bash
# this folder will be created when launch the script
name_folder="Tools"




main(){
  mkdir -p $name_folder

  echo "Updating repositories"
  sudo apt-get update >/dev/null 2>/dev/null

  echo "Installing tmux and nmap:"
  sudo apt install -y tmux nmap wget >/dev/null 2>/dev/null

  # install nmapAutomator
  echo "Downloading NmapAutomator:"
  rm -f nmapAutomator.sh # delete old version
  wget https://raw.githubusercontent.com/21y4d/nmapAutomator/master/nmapAutomator.sh >/dev/null 2>/dev/null
  if [[ "$?" != 0 ]]; then
    echo "Error downloading NmapAutomator"
  else
    echo "  Finish download"
    chmod +x nmapAutomator.sh # give execution permision
  fi

  # install linPEAS
  # https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
  echo "Downloading linPEAS:"
  rm -f linpeas.sh  # delete old version
  wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh >/dev/null 2>/dev/null
  if [[ "$?" != 0 ]]; then
    echo "Error downloading linPEAS"
  else
    echo "  Finish download"
    chmod +x linpeas.sh # give execution permision
  fi
}

main
