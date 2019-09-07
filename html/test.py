#!/usr/bin/env python

import RPi.GPIO as GPIO
from time import sleep

GPIO.setmode(GPIO.BCM)

GPIO.setup(9, GPIO.OUT, initial=GPIO.LOW)
# while True:
GPIO.output(9, GPIO.HIGH)
sleep(0.2)
GPIO.output(9, GPIO.LOW)
sleep(0.2)

GPIO.cleanup()