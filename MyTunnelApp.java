/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.p4tutorial.mytunnel;

import com.google.common.collect.Lists;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IPacket;
import org.onlab.packet.Ethernet;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.nio.ByteBuffer;


import static org.slf4j.LoggerFactory.getLogger;

/**
 * MyTunnel application which provides forwarding between each pair of hosts via
 * MyTunnel protocol as defined in mytunnel.p4.
 * <p>
 * The app works by listening for host events. Each time a new host is
 * discovered, it provisions a tunnel between that host and all the others.
 */
@Component(immediate = true)
public class MyTunnelApp {

    private static final String APP_NAME = "org.onosproject.p4tutorial.mytunnel";

    // Default priority used for flow rules installed by this app.
    private static final int FLOW_RULE_PRIORITY = 100;

    private final HostListener hostListener = new InternalHostListener();
    private ApplicationId appId;
    private AtomicInteger nextTunnelId = new AtomicInteger();

    private static final Logger log = getLogger(MyTunnelApp.class);

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    //--------------------------------------------------------------------------
    // ONOS core services needed by this application.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PacketService packetService;


    //--------------------------------------------------------------------------
    //--------------------------------------------------------------------------

    @Activate
    public void activate() {
        // Register app and event listeners.
        log.info("Starting...");
        appId = coreService.registerApplication(APP_NAME);
        hostService.addListener(hostListener);
        packetService.addProcessor(processor, PacketProcessor.ADVISOR_MAX + 2);
        log.info("STARTED", appId.id());
    }

    @Deactivate
    public void deactivate() {
        // Remove listeners and clean-up flow rules.
        log.info("Stopping...");
        hostService.removeListener(hostListener);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("STOPPED");
    }

    /**
     * Provisions a tunnel between the given source and destination host with
     * the given tunnel ID. The tunnel is established using a randomly picked
     * shortest path based on the given topology snapshot.
     *
     *
     * @param srcHost tunnel source host
     * @param dstHost tunnel destination host
     * @param topo    topology snapshot
     */
    private void provisionTunnel(Host srcHost, Host dstHost, Topology topo) {

        // Get all shortest paths between switches connected to source and
        // destination hosts.

        // host的封包進入topo遇到的第一個sw和最後一個sw
        DeviceId srcSwitch = srcHost.location().deviceId();
        DeviceId dstSwitch = dstHost.location().deviceId();

        List<Link> pathLinks;
        Set<Path> allPaths;

        if (srcSwitch.equals(dstSwitch)) {
            // Source and dest hosts are connected to the same switch.
            allPaths = Collections.emptySet();
            pathLinks = Collections.emptyList();
        } else {
            // Compute shortest path.
            allPaths = topologyService.getPaths(topo, srcSwitch, dstSwitch);
            if (allPaths.size() == 0) {
                log.warn("No paths between {} and {}", srcHost.id(), dstHost.id());
                return;
            }
            //pathLinks = pickFirstPath(allPaths).links();
            pathLinks = Lists.newArrayList();
        }
        // Insert tunnel transit rules on all switches in the path, excluded the
        // last one.
        for (IpAddress dstIpAddr : dstHost.ipAddresses()) {
            for(Path eachpath : allPaths){
              pathLinks = eachpath.links();
              for (Link link : pathLinks) {
                  DeviceId sw = link.src().deviceId();
                  PortNumber port = link.src().port();
                  String dst = link.dst().deviceId().toString().substring(8);
                  byte[] dstmac = dst.getBytes();
                  if(port.toLong() == 1 || port.toLong() == 2){
                      log.info("bbbbbbbbbb {}",port.toLong());
                      insertIpv4ForwardRule(sw, port, dstIpAddr, dstmac);
                  }
                  if(link == pathLinks.get(pathLinks.size() - 1)){
                    //log.info("******");
                    insertModifyNcHeaderRule(sw);
                  }
              }
            }
            // last switch flow entry
            PortNumber lastswitch_port = dstHost.location().port();
            byte[] dsthostmac = dstHost.mac().toBytes();
            insertIpv4ForwardRule(dstSwitch, lastswitch_port, dstIpAddr, dsthostmac);
            log.info("//////////");
            insertRemoveNcHeaderRule(dstSwitch, lastswitch_port);
        }
        //insertRomveHeaderRule(dstSwitch, egressSwitchPort);把port當 table remove_header match的field
        log.info("** Completed provisioning of (srcHost={} dstHost={})",
                 srcHost.id(), dstHost.id());
    }

    /**
     * Generates and insert a flow rule to perform the tunnel INGRESS function
     * for the given switch, destination IP address and tunnel ID.
     *
     * @param switchId  switch ID
     * @param outPort IP address to forward inside the tunnel
     */
    private void insertRemoveNcHeaderRule(DeviceId switchId,
                                         PortNumber outPort) {


        PiTableId RemoveNcHeaderTableId = PiTableId.of("c_egress.remove_header");

        PiMatchFieldId RemoveNcPortMatchFieldId = PiMatchFieldId.of("standard_metadata.egress_port");
        PiCriterion match = PiCriterion.builder()
                .matchExact(RemoveNcPortMatchFieldId, (int) outPort.toLong())
                .build();

        PiActionId EgressActionId = PiActionId.of("c_egress.remove_NC");
        PiAction action = PiAction.builder()
                .withId(EgressActionId)
                .build();

        log.info("Inserting remove NC header rule on switch {}: table={}, match={}, action={}",
                 switchId, RemoveNcHeaderTableId, match, action);

        insertPiFlowRule(switchId, RemoveNcHeaderTableId, match, action);
    }

    /**
    * @param switchId  switch ID
    */
   private void insertModifyNcHeaderRule(DeviceId switchId) {


       PiTableId ModifyNcHeaderTableId = PiTableId.of("c_egress.modifyNCaction");

       PiMatchFieldId ModifyNcHeaderMatchFieldId = PiMatchFieldId.of("meta.nextdecode");
       PiCriterion match = PiCriterion.builder()
               .matchExact(ModifyNcHeaderMatchFieldId, 0)
               .build();

       PiActionId EgressActionId = PiActionId.of("c_egress.decoding_prim");
       PiAction action = PiAction.builder()
               .withId(EgressActionId)
               .build();

       log.info("Inserting modify NC header rule on switch {}: table={}, match={}, action={}",
                switchId, ModifyNcHeaderTableId, match, action);

       insertPiFlowRule(switchId, ModifyNcHeaderTableId, match, action);
   }

    /**
     * Generates and insert a flow rule to perform the tunnel FORWARD/EGRESS
     * function for the given switch, output port address and tunnel ID.
     *
     * @param switchId switch ID
     * @param outPort  output port where to forward tunneled packets
     * @param dstIpAddr
     * @param macAddr
     */
    private void insertIpv4ForwardRule(DeviceId switchId,
                                         PortNumber outPort,
                                         IpAddress dstIpAddr,
                                         byte[] macAddr) {

        PiTableId ipv4ForwardTableId = PiTableId.of("c_ingress.ipv4_lpm");

        // Exact match on tun_id
        PiMatchFieldId ipv4MatchFieldId = PiMatchFieldId.of("hdr.ipv4.dstAddr");
        PiCriterion match = PiCriterion.builder()
                .matchLpm(ipv4MatchFieldId, dstIpAddr.toOctets(), 32)
                .build();

        // Action depend on isEgress parameter.
        // if true, perform tunnel egress action on the given outPort, otherwise
        // simply forward packet as is (set_out_port action).
        PiActionParamId portParamId = PiActionParamId.of("port");
        PiActionParamId macParamId = PiActionParamId.of("dstAddr");
        PiActionParam portParam = new PiActionParam(portParamId, (short) outPort.toLong());
        PiActionParam macParam = new PiActionParam(macParamId, macAddr);

        final PiAction action;
        PiActionId egressActionId = PiActionId.of("c_ingress.ipv4_forward");
        action = PiAction.builder()
                .withId(egressActionId)
                .withParameter(portParam)
                .withParameter(macParam)
                .build();

        log.info("Inserting ipv4forwarding rule on switch {}: table={}, match={}, action={}",
                 switchId, ipv4ForwardTableId, match, action);


        insertPiFlowRule(switchId, ipv4ForwardTableId, match, action);
    }

    /**
     * Inserts a flow rule in the system that using a PI criterion and action.
     *
     * @param switchId    switch ID
     * @param tableId     table ID
     * @param piCriterion PI criterion
     * @param piAction    PI action
     */
    private void insertPiFlowRule(DeviceId switchId, PiTableId tableId,
                                  PiCriterion piCriterion, PiAction piAction) {
        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(switchId)
                .forTable(tableId)
                .fromApp(appId)
                .withPriority(FLOW_RULE_PRIORITY)
                .makePermanent()
                .withSelector(DefaultTrafficSelector.builder()
                                      .matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder()
                                       .piTableAction(piAction).build())
                .build();
        flowRuleService.applyFlowRules(rule);
    }

    private Path pickFirstPath(Set<Path> paths) {
        int item = 0;
        //int item = new Random().nextInt(paths.size());
        List<Path> pathList = Lists.newArrayList(paths);
        return pathList.get(item);
    }

    /**
     * A listener of host events that provisions two tunnels for each pair of
     * hosts when a new host is discovered.
     */
    private class InternalHostListener implements HostListener {

        @Override
        public void event(HostEvent event) {
            if (event.type() != HostEvent.Type.HOST_ADDED) {
                // Ignore other host events.
                return;
            }
            synchronized (this) {
                // Synchronizing here is an overkill, but safer for demo purposes.
                Host host = event.subject();
                Topology topo = topologyService.currentTopology();
                for (Host otherHost : hostService.getHosts()) {
                    if (!host.equals(otherHost)) {
                        //封包往返都要建flow entry
                        provisionTunnel(host, otherHost, topo);
                        provisionTunnel(otherHost, host, topo);
                    }
                }
            }
        }
    }

    private class ReactivePacketProcessor implements PacketProcessor{

      @Override
      public void process(PacketContext context){
        if (context.isHandled()) {
          return;
        }

        InboundPacket pktin = context.inPacket();
        Ethernet ppp = pktin.parsed();
        //ByteBuffer pktbuffer = pktin.unparsed();
        //byte [] originalpkt = new byte[pktbuffer.remaining()];
        //pktbuffer.get(originalpkt);

        byte[] OutputEtherPktByte = ppp.serialize();
        String etherpktstr = ppp.bytesToHex(OutputEtherPktByte);

        int[] tmp1 = new int[4];
        for(int x = 0; x <= 3; x++){
          tmp1[x] = Byte.toUnsignedInt(OutputEtherPktByte[OutputEtherPktByte.length - 4 + x]);
        }

        GF256Matrix matrix1 = new GF256Matrix(new int[][]{
            {tmp1[0], tmp1[1]},
            {tmp1[2], tmp1[3]}
        });

        GF256Matrix matrix2 = matrix1.inverse();
        for(int i = 0; i < 2; i++){
            for(int j = 0; j < 2; j++){
              tmp1[2*i+j] = matrix2.getElement(i, j);
            }
        }

        for(int x = 0; x <= 3; x++){
          OutputEtherPktByte[OutputEtherPktByte.length - 4 + x] = (byte)tmp1[x];
        }

        ByteBuffer OutputPktBuffer = ByteBuffer.wrap(OutputEtherPktByte);
        PortNumber p = pktin.receivedFrom().port();

        //pktin.receivedFrom().port() does not work
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(p.portNumber(255)).build();
        OutboundPacket pktout = new DefaultOutboundPacket(pktin.receivedFrom().deviceId(), treatment, OutputPktBuffer);
        packetService.emit(pktout);

        log.info("receive paket_in pkt={} ={}", etherpktstr, OutputEtherPktByte);
      }
    }
}
