# sdn-project
An old college project

Project that allows you to route the traffic between two networks through two different paths (s1-s2-s3-s6 or s1-s4-s5-s6). 
Path switching can be done either manually (manual.py and path.cfg files) or automatically, based on bandwidth threshold which is set in pathbw.cfg file. 
If the bandwidth (set in iperf for example) is higher than threshold then packets go through s1-s4-s5-s6 path, otherwise packets go through s1-s2-s3-s6 path.

Network topology:
![visualization](https://user-images.githubusercontent.com/12773967/204281541-9a867b5b-9098-4353-8d1d-7af95ea7bf84.png)

Components used: Mininet and RYU controller
