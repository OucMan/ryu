1. Incoming packet to the switch-1 with SRC Addr: Real & DST Addr: Virtual
2. Packet-in message to the controller
3. Controller checks if the destination address is directly connected to the current switch.
4. If not(Controller receives a false message),Controller gives an action asking the src address to be changed to virtual since it was real, therefore, the next switch receives a packet with SRC Addr: Virtual & DST Addr: Virtual.
5. Otherwise, Controller gives an action asking the dst address to be changed to real, and the message is sent to the destination.

