#!/bin/sh

VER=5.4.161
BUILD_KERNEL=1

SRC="/usr/src"
UPDATES="updates"

HOME=`readlink -f $0 | xargs dirname`
CONF=$HOME/conf/linux-${VER}.config
FILE_LIST=$HOME/conf/$UPDATES
VER_MAJOR=`echo $VER | awk -F '.' '{print $1}'`
KERNEL_SITE="https://mirrors.edge.kernel.org/pub/linux/kernel/v${VER_MAJOR}.x/"

if [ ! -e $FILE_LIST ]; then
    echo "Error: $FILE_LIST does not exist"
    exit
fi

if [ ! -e $CONF ]; then
    echo "Error: $CONF does not exist"
    exit
fi

if [ `which apt-get` = "apt-get not found" ]; then
    echo "apt-get not found"
    exit
fi

apt-get update
apt-get install -y build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison liblz4-tool

TARGET=$SRC/linux-$VER
if [ -e $TARGET ]; then
    echo "Removing $TARGET ..."
    rm -rf $TARGET
fi
FILE_NAME=linux-${VER}.tar.xz
KPKG=$HOME/kernel/$FILE_NAME
if [ ! -e $KPKG ]; then
    wget $KERNEL_SITE$FILE_NAME -P $HOME/kernel/
    if [ ! -e $KPKG ]; then
        echo "Error: $KPKG does not exist"
        exit
    fi  
fi
tar xf $KPKG -C $SRC
cat $FILE_LIST | while read i; do
    if [ "$i" != "" ]; then
        name=`basename $i`
        file=$HOME/src/$name
        if [ ! -e $file ]; then
            echo "Error: $file does not exist"
	        exit
        fi
        echo "update $i"
        target=$TARGET/$i
        cp $file $target
    fi
done
cp $CONF $TARGET/.config
cd $TARGET
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
if [ "$BUILD_KERNEL" = "1" ]; then
    make
    make modules_install
    make install
    update-grub
fi
