ICON=icon.png
ICON_DIR=$HOME/.local/share/gdata
ICON_PATH=$ICON_DIR/$ICON
SERVICE_DIR=$HOME/.local/share/kservices5 # Get with: kf5-config --path services
SERVICE_FILE=getGdataVerdict.desktop
SERVICE_PATH=$SERVICE_DIR/$SERVICE_FILE
BINARY_DEST_DIR=$HOME/.local/bin/gdata

# Kill all current Dolphin instances
pkill dolphin

# Remove artifacts
rm $SERVICE_PATH
rm -rf $ICON_DIR
rm -rf $BINARY_DEST_DIR
