#!/usr/bin/python

import re, sys
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.util import dumpNodeConnections, quietRun
from mininet.log import setLogLevel, info, error
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.link import TCLink, Intf

if __name__ == '__main__':
        setLogLevel( 'info' )

        info( '*** Creating network ***\n' )
        net = Mininet(link=TCLink)

        info( '\n*** Creating Controlers ***\n' )
        net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )
        c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633 )

        info( '\n*** Creating Switches ***\n' )
        s1 = net.addSwitch( 's1' , ip='172.16.0.11' , mac='00:00:00:00:00:11' , port='6634' , switch='ovsk' )
        s2 = net.addSwitch( 's2' , ip='172.16.0.12' , mac='00:00:00:00:00:12' , port='6634' , switch='ovsk' )
        s3 = net.addSwitch( 's3' , ip='172.16.0.13' , mac='00:00:00:00:00:13' , port='6634' , switch='ovsk' )
        s4 = net.addSwitch( 's4' , ip='172.16.0.14' , mac='00:00:00:00:00:14' , port='6634' , switch='ovsk' )
        s5 = net.addSwitch( 's5' , ip='172.16.0.15' , mac='00:00:00:00:00:15' , port='6634' , switch='ovsk' )
        s6 = net.addSwitch( 's6' , ip='172.16.0.16' , mac='00:00:00:00:00:16' , port='6634' , switch='ovsk' )

        info( '\n*** Creating Hosts ***\n' )
        h1 = net.addHost( 'h1' , ip='172.16.0.1' , mac='00:00:00:00:00:01' )
        h2 = net.addHost( 'h2' , ip='172.16.0.2' , mac='00:00:00:00:00:02' )

        info( '\n*** Creating Physical Interfaces ***\n' )

        info( '\n*** Creating Links ***\n' )
        net.addLink( s1, s2, delay='100ms' )
        net.addLink( s2, s3, delay='100ms' )
        net.addLink( s3, s6, delay='100ms' )
        
        net.addLink( s1, s4, delay='10ms' )
        net.addLink( s4, s5, delay='10ms' )
        net.addLink( s5, s6, delay='10ms' )
        
        net.addLink( h1, s1, delay='10ms' )
        net.addLink( h2, s6, delay='10ms' )

        net.start()
        s1.start([c0])
        s2.start([c0])
        s3.start([c0])
        s4.start([c0])
        s5.start([c0])
        s6.start([c0])
        
        h1.cmd("ping -c4 h2")
        CLI(net)	
        net.stop()
