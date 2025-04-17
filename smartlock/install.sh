#!/usr/bin/env bash

# For Linux or MacOS
# Install standalone python3
MINIFORGE_NAME="Miniforge3-$(uname)-$(uname -m)"
curl -L -O "https://github.com/conda-forge/miniforge/releases/download/25.1.1-0/$MINIFORGE_NAME.sh"
bash $MINIFORGE_NAME.sh -b -p venv
rm $MINIFORGE_NAME.sh

# Install python packages
source venv/bin/activate
pip install -r requirements.txt

echo "Done, now run \"bash run.sh --gui\""