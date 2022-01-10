#!/usr/bin/env bash

cd /tmp/src

cp -rp -- /tmp/src/target/poc-middleware-*.war "$TOMCAT_APPS/poc-middleware.war"
cp -- /tmp/src/conf/ocp/poc-middleware.xml "$TOMCAT_APPS/poc-middleware.xml"

export WAR_FILE=$(readlink -f "$TOMCAT_APPS/poc-middleware.war")
