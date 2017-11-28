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

#
# TODO:
# Usage:
#   sdsync.sh [-b] [-s SRC] DEST
#
#   -b will cause a backup to be run immediately, skipping
#        the dry-run
#   -s will supply a specific SRC folder (if not provided,
#          will attempt to auto-detect)
#   DEST is the backup destination, shortcuts can be used
#

#
# Future ideas:
# - Reimplement in Python, integrate with metasync as
#     separate functionality
# - Possibly do EXIF datetime adjustment for TZ/location
#     Would be non-trivial, maybe easier to keep using 
#     excellent regex.info GPS plugin and perform file
#     rename/sync with new datetime while within LR
#     catalog.  Want to avoid solely external rename
#     which would cause a rescan of catalog/on disk
#     data.  Maybe a LR plugin to a post-import file
#     rename would work.
#


### Do the rsync ###
function do_backup()
{
    SRC_ARG="$1"
    DEST_ARG="$2"

    rsync -av --progress "$SRC_ARG" "$DEST_ARG"
}


### main() ###

#ARGS=`getopt bs: $*`
#if [ "$?" != 0 ]; then
#    echo "Usage: $0 [-b] [-s SRC] DEST"
#    exit 2
#fi
#set -- $ARGS
#
#for i
#do
#    case "$i"
#    in
#        -b)
#            BACKUP=1

#
# TODO: Autodetect SRC (eg: SD card)
# This may be good place to start?
#   mount | egrep disk[0-9]s1
#
SRC1="/Volumes/Untitled"
SRC2="/Volumes/NO NAME"

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

# Determine which data to backup
# TODO: Support handling multiple sources with one execution
SRCDATA="$SRC/DCIM/100MSDCF"
#SRCDATA="$SRC/DCIM/101PHOTO"
#SRCDATA="$SRC/DCIM/102SAVED"
#SRCDATA="$SRC/PRIVATE/M4ROOT/CLIP"

if [ ! -d "$SRCDATA" ]; then
    echo "[error] Source path $SRCDATA not detected, aborting"
    exit 1
fi

if [ -z "$1" ]; then
    echo "[error] Destination argument required (one of [sdbackup, photography]), aborting"
    exit 1
elif [ "$1" == "sdbackup" ]; then
    DEST="/Volumes/SD Backup/Backup"
elif [ "$1" == "photography" ]; then
    DEST="/Volumes/Photography/SD Backup"
else
    echo "[error] Destination argument $1 invalid, aborting"
    exit 1
fi

# Check to ensure that DEST path exists
if [ ! -d "$DEST" ]; then
    echo "[error] Destination path $DEST not detected, aborting"
    exit 1
fi

if [ "$2" == "--backup" ]; then
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
    read -p "Create? [y/N]: " CREATE

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

### Copy data
echo
echo "Starting rsync"
echo "Command:"
echo "rsync -avn --progress \"$SRCDATA/\" \"$DEST/$ID\""
rsync -avn --progress "$SRCDATA/" "$DEST/$ID"
# TODO: Detect state where no data needs to be copied

# Show potential differences
echo
echo -n "Source size (MB): "
du -sm "$SRCDATA"
echo -n "Destination size (MB): "
if [ ! -d "$DEST/$ID" ]; then
    echo "0 $DEST/$ID"
else
    du -sm "$DEST/$ID"
fi

# This can be improved
if [ "$BACKUP" == "y" -o "$BACKUP" == "Y" ]; then
    do_backup "$SRCDATA/" "$DEST/$ID"
else
    read -p "Perform backup? [y/N]: " BACKUP
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
# Inefficient, but simple method
# TODO: Some sort of progress, eg: [current file #/total file #]
rm md5sum.new 2>/dev/null
for f in `/bin/ls`;
do {
    if [ "$f" == "md5sum.txt" ]; then
        continue
    elif [[ "$f" == *"xmp" ]]; then
        continue
    fi
    MD5=$(grep $f md5sum.txt 2>/dev/null)
    if [ "$MD5" == "" ]; then
        # TODO: Provide count + total for progress
        echo "Checksum for $f missing, calculating"
        md5sum "$f" >> md5sum.new
    fi
} done

# If not commited, no automatic way to recalculate
# That functionality could be added as a different
# mode of invocation.
read -p "Append new checksums to md5sum.txt? [y/N]: " COMMIT_MD5
if [ "$COMMIT_MD5" == "y" -o "$COMMIT_MD5" == "Y" ]; then
    cat md5sum.new >> md5sum.txt
    rm md5sum.new 2>/dev/null
else
    echo "Skipping modification of md5sum.txt"
    echo "Calculated new file checksums stored in md5sum.new"
fi

# TODO: Calculate checksums of original files & verify
echo "Files synced to $DEST/$ID"

# Fin #
exit 0
