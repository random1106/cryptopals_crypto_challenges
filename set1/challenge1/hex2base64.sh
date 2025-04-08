#!/bin/bash

hex2base() {

    echo $1 | xxd -r -p | base64

}

hex2base $1