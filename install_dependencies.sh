#!/bin/bash

echo 'if something does not work, try using sudo!'
echo 'sudo bash ./install_dependencies.sh'
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
apt install ./rustscan_2.0.1_amd64.deb -y
apt-get install ffuf -y
pip install googlesearch-python
