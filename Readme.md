## location
* mytunnel.p4:/home/sdn/onos/apps/p4-tutorial/pipeconf/src/main/resources
* MytunnelApp.java:/home/sdn/onos/apps/p4-tutorial/mytunnel/src/main/java/org/onosproject/p4tutorial/mytunnel
* GF256.java:/home/sdn/onos/apps/p4-tutorial/mytunnel/src/main/java/org/onosproject/p4tutorial/mytunnel
* GF256Matrix.java:/home/sdn/onos/apps/p4-tutorial/mytunnel/src/main/java/org/onosproject/p4tutorial/mytunnel
* bmv2.py:/home/sdn/onos/tools/dev/mininet
* bm-commands.sh:/home/sdn/onos/tools/dev/p4vm
* sswitch_CLI.py:/usr/local/lib/python2.7/dist-packages
* antilog_command:/home/sdn
* send1.py,send2.py,receive1.py,receive2.py:/home/sdn

## Running step
``atom $ONOS_ROOT/apps/p4-tutorial/``
1. ONOS
* MytunnelApp (On a first terminal window)
``cd $ONOS_ROOT`` 
`` ONOS_APPS=proxyarp,hostprovider,lldpprovider,drivers.bmv2,p4tutorial.pipeconf,p4tutorial.mytunnel ok clean ``
2. Mininet
* topology (On a second terminal window)
``sudo -E mn --custom $BMV2_MN_PY --switch onosbmv2,loglevel=debug,pipeconf=p4-tutorial-pipeconf --topo mytopo --controller remote,ip=127.0.0.1``
* insert the table entry (On a second terminal window)
``mininet> h1 ping h2``
* Open host xterm (On a second terminal window)
``mininet> xterm h1 h1 h2 h2``
* optional bmv2 log(On a third terminal window)
``bm-log s1``
``bm-log s2``
log file location:/tmp
3. P4Runtime
* insert the clone entry & GF256 log-table Initial value (On a fourth terminal window) 
``source ~/onos/tools/dev/p4vm/bm-commands.sh``(first time only)
``bm-cli s1 < antilog_command.txt``
``bm-cli s2 < antilog_command.txt``
4. testing
* (On h1 xterm)
``send1.py 10.0.0.2 Q``
``send2.py 10.0.0.2 P``
* (On h2 xterm)
``receive1.py``
``receive2.py``

## How to compile P4 program
1. change the directory to ``~/onos/apps/p4-tutorial/pipeconf/src/main/resources``
2. input the command ``make``
