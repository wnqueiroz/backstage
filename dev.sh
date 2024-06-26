#!/bin/bash

. .env && export $(grep -Ev '(^\s*#|^\s*$)' .env | cut -d '=' -f 1)

yarn dev