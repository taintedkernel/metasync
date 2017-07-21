#!/bin/bash

#
# sdsync.sh 
#
# An ugly hack to perform backup/sync of theoritically
# arbitrary directories, but intended to be used with
# memory cards
#
# It utilizes a unique identifier text file located
# on the cards to determine which source card is
# being read from, optionally this identifier can be
# automatically created
#
# After copying the files from source card to a 
# destination folder, the script will calculate
# checksums of the newly copied data and log
# to a file, eventually to be used to identify
# corruption/bad data
#


### Do the rsync ###
function do_backup()
{
    SRC_ARG="$1"
    DEST_ARG="$2"

    rsync -av --progress "$SRC_ARG" "$DEST_ARG"
}


### main() ###

#
# TODO: Autodetect SRC (eg: SD card)
# This may be good place to start?
#   mount | egrep disk[0-9]s1
#
SRC1="/Volumes/Untitled"
SRC2="/Volumes/NO NAME"
#DEST="/Volumes/SD Backup/Backup"
DEST="/Volumes/Photography/SD Backup"

# Check to ensure that one of SRC1 or SRC2 paths exist
if [ ! -d "$SRC1" -a ! -d "$SRC2" ]; then
    echo "[error] Source paths $SRC1 and $SRC2 not detected, aborting"
    exit 1
fi

# If both SRC1 and SRC2 exist, SRC1 has higher priority
if [ -d "$SRC1" ]; then
    SRC=$SRC1
elif [ -d "$SRC2" ]; then
    SRC=$SRC2
fi
SRCDATA="$SRC/DCIM/100MSDCF"

# Check to ensure that DEST path exists
if [ ! -d "$DEST" ]; then
    echo "[error] Destination path $DEST not detected, aborting"
    exit 1
fi

if [ "$1" == "--backup" ]; then
    BACKUP="y"
else
    BACKUP="n"
fi

### Provide a status of existing backups
echo "Detected card backups at $DEST:"
for d in `/bin/ls "$DEST"`;
do {
    echo -n "$d: ";
    COUNT=$(find "$DEST/$d" -type f | wc -l);
    echo "$COUNT files";
} done | sort -k2 -rn

### Check for identifier and create if missing and requested
echo
ID=$(cat "$SRC/id.txt" 2>/dev/null)
if [ "$ID" == "" ]; then
    echo "[error] No ID on card (at $SRC/id.txt) detected"
    read -p "Create? (y/n): " CREATE

    if [ "$CREATE" == "y" -o "$CREATE" == "Y" ]; then
        ID=$(python -c "import uuid; print str(uuid.uuid1()).upper()")
        echo "echo $ID | tee \"$SRC/id.txt\""
        exit 0
    else
        echo "Aborting"
        exit 1
    fi
fi

echo "Source ID $ID detected"

##echo rsync -avn --filter="+ DCIM/" --filter="+ DCIM/**" --filter="- *" /Volumes/Untitled/ "/Volumes/SD Backup/Backup/EA2E5044-EB98-43E8-B251-98C5ED0B484B"
#rsync -avn --filter="+ DCIM/" --filter="+ DCIM/**" --filter="- *" $SRCDATA "$DEST/$ID"
#echo -n 'rsync -avn --filter="+ DCIM/" --filter="+ DCIM/**" --filter="- *" '
#echo $SRCDATA \"$DEST/$ID\"

### Copy data
echo
echo "Starting rsync"
echo "Command:"
echo "rsync -avn --progress \"$SRCDATA/\" \"$DEST/$ID\""
rsync -avn --progress "$SRCDATA/" "$DEST/$ID"

# This can be improved
if [ "$BACKUP" == "y" -o "$BACKUP" == "Y" ]; then
    do_backup "$SRCDATA/" "$DEST/$ID"
else
    read -p "Perform backup? (y/n): " BACKUP
    if [ "$BACKUP" == "y" -o "$BACKUP" == "Y" ]; then
        do_backup "$SRCDATA/" "$DEST/$ID"
    else
        exit 0
    fi
fi

### Calculate checksums of new files
echo
echo "Calculating checksums of new files..."

# Change to our target directory to make this easier
cd "$DEST/$ID"
if [ "$?" -ne 0 ]; then
    echo "[error] unable to change to target directory \"$DEST/$ID\""
fi

# Iterate through $DEST and for each file grep checksum file
# Calculate any that are missing (eg: newly copied data)
rm md5sum.new 2>/dev/null
for f in `/bin/ls`;
do {
    if [ "$f" == "md5sum.txt" ]; then
        continue
    fi
    MD5=$(grep $f md5sum.txt 2>/dev/null)
    if [ "$MD5" == "" ]; then
        echo "Checksum for $f missing, calculating"
        md5sum "$f" >> md5sum.new
    fi
} done

# If not commited, no automatic way to recalculate
# That functionality could be added as a different
# mode of invocation.
read -p "Commit checksums to md5sum.txt? " COMMIT_MD5
if [ "$COMMIT_MD5" == "y" -o "$COMMIT_MD5" == "Y" ]; then
    cat md5sum.new >> md5sum.txt
    rm md5sum.new 2>/dev/null
fi

# Fin #
exit 0
