#!/bin/sh

CURRENT_DIR=`pwd`

if [ "x$1" = "x" ]; then
  echo "Usage: $0 <version>"
  exit
fi

VER=$( echo "$1" | cut -d '-' -f1 )
DEV=$( echo "$1" | cut -d '-' -s -f2 )

echo $DEV
if [ "x$DEV" = "x" ]; then
  VERSION="$VER"
else
  VERSION="$VER-SNAPSHOT"
fi

cd wrappers/java
mvn versions:set -DnewVersion=$VERSION

cd $CURRENT_DIR
