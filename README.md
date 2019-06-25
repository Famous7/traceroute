# traceroute
python3 traceroute using only socket module

## python3 traceroute.py [host] [packet bytes] [-I[ICMP] -U[UDP]] -c [MAX_HOP] -t [TIMEPUT] -p [UDP Port]
  - ex) python3 traceroute.py google.com 100 -I
  - ex) python3 traceroute.py 8.8.8.8 200 -U
  - ex) python3 traceroute.py 8.8.8.8 200 -U -p 53 -c 15 -t 0.1


## Example
 - ICMP
  ![ICMP](/img/ICMP.jpg)

 - UDP
  ![UDP](/img/UDP.jpg)
