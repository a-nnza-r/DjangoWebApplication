#!/usr/bin/env bash

USE_GUI=$1

shift
source venv/bin/activate
python Smartlock.py $USE_GUI