#!/bin/bash

SERVER=$1

mosquitto_sub -h ${SERVER} -t "topic1" -u "davlawrence" -P "passwd"
