#!/bin/bash

# Install the KDE Dolphin plugin to scan files with GDATA VaaS
# run with: ./install.sh -t <token>

ICON_WITHOUT_EXT=icon
ICON=$ICON_WITHOUT_EXT.png
ICON_DIR=$HOME/.local/share/gdata
ICON_PATH=$ICON_DIR/$ICON
ICON_PATH_WITHOUT_EXT=$ICON_DIR/$ICON_WITHOUT_EXT
SERVICE_DIR=$HOME/.local/share/kservices5 # Get with: kf5-config --path services
SERVICE_FILE=getGdataVerdict.desktop
SERVICE_PATH=$SERVICE_DIR/$SERVICE_FILE
BINARY_SRC_PATH=$(pwd)/target/release/gdata_vaas_ui
BINARY_DEST_DIR=$HOME/.local/bin/gdata
BINARY_DEST_PATH=$BINARY_DEST_DIR/gdata-vaas


# Read the VaaS token from command line arguments
SHORT=t:
LONG=token:
OPTS=$(getopt --options $SHORT --longoptions $LONG -- "$@")
eval set -- "$OPTS"

if [ "$#" -ne 3 ];  then 
    echo "Usage: $0 -t <token>"
    exit 1
fi

while :
do
  case "$1" in
    -t | --token )
      VAAS_TOKEN="$2"
      shift 2
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unknown flag: $1"
      ;;
  esac
done

# Kill all current Dolphin instances
pkill dolphin

# Create directory if it doesn't exist
mkdir -p $SERVICE_DIR
mkdir -p $ICON_DIR
mkdir -p $BINARY_DEST_DIR

# Copy files
cp ./$SERVICE_FILE $SERVICE_PATH
cp ./$ICON $ICON_PATH
cp $BINARY_SRC_PATH $BINARY_DEST_PATH

# Replace the icon path in the desktop file
sed -i 's!REPLACE_WITH_ICON_PATH!'"$ICON_PATH_WITHOUT_EXT"'!' $SERVICE_PATH
sed -i 's!REPLACE_WITH_BINARY_PATH!'"$BINARY_DEST_PATH"'!' $SERVICE_PATH

# Replace the VaaS token in the desktop file
sed -i 's!REPLACE_WITH_TOKEN!'"$VAAS_TOKEN"'!' $SERVICE_PATH