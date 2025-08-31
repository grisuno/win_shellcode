#!/bin/bash
sudo apt install python3-pip python3-venv
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
