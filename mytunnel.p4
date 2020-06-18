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

 /*
  * This program describes a pipeline implementing a very simple
  * tunneling protocol called MyTunnel. The pipeline defines also table called
  * t_l2_fwd that provides basic L2 forwarding capabilities and actions to
  * send packets to the controller. This table is needed to provide
  * compatibility with existing ONOS applications such as Proxy-ARP, LLDP Link
  * Discovery and Reactive Forwarding.
  */

#include <core.p4>
#include <v1model.p4>

#define MAX_PORTS 255

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6


typedef bit<9> port_t;
const port_t CPU_PORT = 255;

const bit<48> decodeswitch = 0x000000022200;
const bit<16> ETH_TYPE_IPV4 = 0x800;
const bit<8>  TYPE_NC = 0x90;
const bit<8>  TYPE_TCP = 0x06;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
#define allencodingnumber 3
#define payloadsize 8
#define allpktsize 184 /*176(16(do not encoding)+160)+11648(payloadsize1456*8)*/
#define decodingnumber 2

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<128> other;
}

header NC_t{
    bit<4>  primitive;
    bit<12> label;
    bit<8>  coeff1;
    bit<8>  coeff2;
}

header NC_e{
    bit<8>  excoeff1;
    bit<8>  excoeff2;
}

header payload_t{
    bit<payloadsize>    input;
}

// Packet-in header. Prepended to packets sent to the controller and used to
// carry the original ingress port where the packet was received.
@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> a;
}

// For convenience we collect all headers under the same struct.
struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    NC_t		 NC;
    NC_e         NCextra;
    tcp_t		 tcp;
    payload_t    payload;
}

// Metadata can be used to carry information from one table to another.
struct metadata_t {
    bit<2>  nextdecode;
    bit<32> packet_length;
    bit<2>  encodingstatus;
    bit<1>  decodingstatus;
    bit<1>  encodingOK;
    bit<1>  decodingOK;
    bit<8>  enflowID;/*編碼當前處理第幾個flow*/
    bit<8>  deflowID;/*解碼當前處理第幾個flow*/
    bit<12> debatch_now;/*當前處理第幾個批次 因為NC label最後會設為無效 DLNC無法使用*/
    bit<32> session;
    bit<1> toController;
    bit<1> recvReq;
    bit<16> pkt1coeff;
    bit<16> pkt2coeff;
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser c_parser(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    // A P4 parser is described as a state machine, with initial state "start"
    // and final one "accept". Each intermediate state can specify the next
    // state by using a select statement over the header fields extracted.
    state start {
        meta.packet_length = standard_metadata.packet_length;
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }


    state parse_packet_out {
        meta.packet_length = meta.packet_length - 2;
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        meta.packet_length = meta.packet_length - 14;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.packet_length = meta.packet_length - 20;
        transition select(hdr.ipv4.protocol) {
            TYPE_NC : parse_NC;
            TYPE_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_NC{
        packet.extract(hdr.NC);
        meta.packet_length = meta.packet_length - 4;
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_extraNC;
            default: parse_tcp;
        }
    }

    state parse_extraNC{
        packet.extract(hdr.NCextra);
        meta.packet_length = meta.packet_length - 2;
        transition accept;
    }

    state parse_tcp{
    	packet.extract(hdr.tcp);
    	meta.packet_length = meta.packet_length - 20;
    	transition parse_payload;
    }

    state parse_payload{
        packet.extract(hdr.payload);
        transition accept;
    }

}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata) {

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).

        // 送往controller要加上packe_in header不然controller會解析錯誤
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port;
    }


    action drop() {
        mark_to_drop();
    }

    // Table counter used to count packets and bytes matched by each entry of
    // t_l2_fwd table.
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;

    action ipv4_forward(egressSpec_t port, macAddr_t dstAddr) {
        standard_metadata.egress_spec = port;
        if(!hdr.NCextra.isValid()){
            hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
            hdr.ethernet.dst_addr = dstAddr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        default_action = drop();
    }

    table t_l2_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dst_addr           : ternary;
            hdr.ethernet.src_addr           : ternary;
            hdr.ethernet.ether_type         : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            drop;
            NoAction;
        }
        default_action = NoAction();
        counters = l2_fwd_counter;
    }



    // Defines the processing applied by this control block. You can see this as
    // the main function applied to every packet received by the switch.
    apply {
        if (standard_metadata.ingress_port == CPU_PORT && !hdr.NC.isValid()) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        }
        else {
            // Packet received from data plane port.
            // Applies table t_l2_fwd to the packet.
            if (t_l2_fwd.apply().hit) {
                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.
                return;
            }
            if (hdr.ipv4.isValid() && meta.toController == 0){
                ipv4_lpm.apply();
            }
            if (meta.toController == 1){
                hdr.NC.setValid();
                hdr.ipv4.protocol = 0x90;
                hdr.NC.primitive = 4;
                hdr.NC.label = meta.debatch_now;
                hdr.NC.coeff1 = meta.pkt1coeff[15:8];
                hdr.NC.coeff2 = meta.pkt1coeff[7:0];
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
                hdr.NCextra.setValid();
                hdr.NCextra.excoeff1 = meta.pkt2coeff[15:8];
                hdr.NCextra.excoeff2 = meta.pkt2coeff[7:0];
                hdr.tcp.setInvalid();
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - 20;
                hdr.payload.setInvalid();
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - payloadsize/8;
                send_to_cpu();
            }
        }
        if(standard_metadata.ingress_port == CPU_PORT && hdr.NC.isValid()){
                hdr.packet_out.setInvalid();
                meta.recvReq = 1;
        }

        // Update port counters at index = ingress or egress port.
        if (standard_metadata.egress_spec < MAX_PORTS) {
            tx_port_counter.count((bit<32>) standard_metadata.egress_spec);
        }
        if (standard_metadata.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) standard_metadata.ingress_port);
        }
     }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<10>>(256) antilog_buffer;
    register<bit<8>>(1025) log_buffer;
    register<bit<allpktsize>>(1000) codingbuffer0;
    register<bit<allpktsize>>(1000) codingbuffer1;
    register<bit<4>>(1000) batch_number;
    register<bit<32>>(2) storecounter;
    register<bit<32>>(1) codingcounter;

    bit<8>  combinetmp0;
    bit<8>  combinetmp1;
    bit<8>  addtmp;
    bit<8>  multitmp;
    bit<8>  divtmp;

    bit<32> storecountertmp;
    bit<32> codingcountertmp;
    bit<allpktsize> buffertmp0;
    bit<allpktsize> buffertmp1;
    bit<32> checktmp0;
    bit<32> checktmp1;
    bit<1>  dropflag = 0;
    bit<4>  batchtmp = 0;


    action drop() {
        mark_to_drop();
    }

    action encoding_prim(bit<8> flowID){
        hdr.NC.primitive = 4w2;
        meta.enflowID = flowID;
    }

    action noaction_prim(){
        hdr.NC.primitive = 4w0;
    }

    action decoding_prim(){
        hdr.NC.primitive = 4w3;
    }

    action remove_NC(){
        hdr.NC.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 4;
        hdr.ipv4.protocol = 0x06;
    }

    action GF_addition(bit<8> a, bit<8> b){
    	addtmp = a ^ b;
    }

    action GF_division(bit<8> e,bit<8> f){
        bit<10>  divreadtmp0;
        bit<10>  divreadtmp1;
    	antilog_buffer.read(divreadtmp0,(bit<32>)e);
    	antilog_buffer.read(divreadtmp1,(bit<32>)f);

    	divreadtmp0 = divreadtmp0 + 255;
    	log_buffer.read(divtmp, (bit<32>)divreadtmp0 - (bit<32>)divreadtmp1);
    }

    action GF_multiplication(bit<8> c,bit<8> d){
        bit<10>  mulreadtmp0;
        bit<10>  mulreadtmp1;
    	antilog_buffer.read(mulreadtmp0,(bit<32>)c);
    	antilog_buffer.read(mulreadtmp1,(bit<32>)d);
    	log_buffer.read(multitmp,(bit<32>)mulreadtmp0 + (bit<32>)mulreadtmp1);

    }
    action coeffgenerator(){
    	random(hdr.NC.coeff1,8w1,8w255);
    	random(hdr.NC.coeff2,8w1,8w255);
    }

    action enstoreflow0(){
    	storecounter.read(storecountertmp,0);
    	if(storecountertmp == 1000){
    		storecountertmp = 0;
    	}
    	codingbuffer0.write(storecountertmp,hdr.NC.coeff1++hdr.NC.coeff2++
    	hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
    	storecountertmp = storecountertmp + 1;
    	storecounter.write(0,storecountertmp);
    }

    action enstoreflow1(){
    	storecounter.read(storecountertmp,1);
    	if(storecountertmp == 1000){
    		storecountertmp = 0;
    	}
		codingbuffer1.write(storecountertmp,hdr.NC.coeff1++hdr.NC.coeff2++
    	hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
    	storecountertmp = storecountertmp + 1;
    	storecounter.write(1,storecountertmp);
    }

    action destoreflow0(){
    	codingbuffer0.write((bit<32>)hdr.NC.label,hdr.NC.coeff1++hdr.NC.coeff2++
    	hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
    	batchtmp = batchtmp + 1;
    	batch_number.write((bit<32>)hdr.NC.label,batchtmp);

    }

    action destoreflow1(){
    	codingbuffer1.write((bit<32>)hdr.NC.label,hdr.NC.coeff1++hdr.NC.coeff2++
    	hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
    	batchtmp = batchtmp + 1;
    	batch_number.write((bit<32>)hdr.NC.label,batchtmp);
    }

    action linearcombine(inout bit<8> z,bit<8> x,bit<8> y,bit<8> coef1,bit<8> coef2){
		GF_multiplication(coef1,x);
		combinetmp0 = multitmp;
		GF_multiplication(coef2,y);
		combinetmp1 = multitmp;
		GF_addition(combinetmp0,combinetmp1);
		z = addtmp;
    }

    action encodeall(inout bit<allpktsize> b0,inout bit<allpktsize> b1,inout bit<allpktsize> pz,bit<8> coeff1,bit<8> coeff2){
    	b0 = b0 << 16;b1 = b1 << 16;/*coeff do not encoding*/
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    	b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
    	linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8],coeff1,coeff2);
    }

    action gaussian(inout bit<8> p0,inout bit<8> p1,bit<8> y1,bit<8> y2,bit<8> a1,bit<8> b1,bit<8> a2,bit<8> b2){
    	bit<8> B2 = b2;
    	bit<8> Y2 = y2;/*這些參數運算過程會替換 但不想改變原數值*/

		GF_division(a2,a1);
		/*
		GF_multiplication(divtmp,a1);
		GF_addition(multitmp,a2);
		a2 = addtmp;
		*/
		GF_multiplication(divtmp,b1);
		GF_addition(multitmp,B2);
		B2 = addtmp;
		GF_multiplication(divtmp,y1);
		GF_addition(multitmp,Y2);
		Y2 = addtmp;

		GF_division(Y2,B2);
		p1 = divtmp;
		GF_multiplication(divtmp,b1);
		GF_addition(multitmp,y1);

		GF_division(addtmp,a1);
		p0 = divtmp;
    }

    action decodeall(inout bit<allpktsize> db0,inout bit<allpktsize> db1){
    	bit<8>	db0coe0 = db0[allpktsize-1:allpktsize-8];
    	bit<8>	db0coe1 = db0[allpktsize-9:allpktsize-16];
    	bit<8>	db1coe0 = db1[allpktsize-1:allpktsize-8];
    	bit<8>	db1coe1 = db1[allpktsize-9:allpktsize-16];
    	db0 = db0 << 16;db1 = db1 << 16;/*coeff do not encoding*/
   	    bit<allpktsize> ans0 = 0;
   	    bit<allpktsize> ans1 = 0;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
   	    db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
   	    gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);

    	codingbuffer0.write((bit<32>)meta.debatch_now,ans0);
		codingbuffer1.write((bit<32>)meta.debatch_now,ans1);
    }

    action pktrecovery(bit<allpktsize> pktinfo){
		hdr.tcp.srcPort = pktinfo[allpktsize-17:allpktsize-32];
		hdr.tcp.dstPort = pktinfo[allpktsize-33:allpktsize-48];
    	hdr.tcp.other = pktinfo[allpktsize-49:allpktsize-176];
    	hdr.payload.input = pktinfo[allpktsize-177:0];
    }

    action commonDLNC(bit<8> coe1,bit<8> coe2){
    	bit<allpktsize> decommontmp = 0;
    	codingbuffer0.read(buffertmp0,(bit<32>)meta.debatch_now);
		codingbuffer1.read(buffertmp1,(bit<32>)meta.debatch_now);
        encodeall(buffertmp0,buffertmp1,decommontmp,coe1,coe2);
        pktrecovery(decommontmp);
        meta.decodingstatus = meta.decodingstatus + 1;
    }

    action DLNC1(){
        commonDLNC(meta.pkt1coeff[15:8],meta.pkt1coeff[7:0]);
        clone3(CloneType.E2E, 350, {standard_metadata , meta});
    }

    action DLNC2(){
        commonDLNC(meta.pkt2coeff[15:8],meta.pkt2coeff[7:0]);
    	batchtmp = 0;
    	batch_number.write((bit<32>)meta.debatch_now,batchtmp);
    }

    action commonLNC(){
    	bit<allpktsize> commontmp = 0;
    	codingcounter.read(codingcountertmp,0);
    	codingbuffer0.read(buffertmp0,(bit<32>)codingcountertmp);
		codingbuffer1.read(buffertmp1,(bit<32>)codingcountertmp);
		encodeall(buffertmp0,buffertmp1,commontmp,hdr.NC.coeff1,hdr.NC.coeff2);
		pktrecovery(commontmp);
    	hdr.NC.label = (bit<12>)codingcountertmp;
        meta.encodingstatus = meta.encodingstatus + 1;
        meta.session = meta.session + 1;// for clone

    }
    action LNC1(){
		coeffgenerator();
    	commonLNC();
        //每個engress block只能呼叫一次clone
        clone3(CloneType.E2E, meta.session, {standard_metadata , meta});
    }


    action LNC_last(){
		coeffgenerator();
    	commonLNC();
    	/*最後一個LNC需要計數已編碼數量*/
    	codingcountertmp = codingcountertmp + 1;
    	if(codingcountertmp == 1000){
    		codingcountertmp = 0;
    	}
    	codingcounter.write(0,codingcountertmp);
    }

    action decodingcheck(){
        if(batchtmp == decodingnumber){
        	meta.decodingOK = 1;
        }
    }

    action encodingcheck(){
        codingcounter.read(codingcountertmp,0);
        storecounter.read(checktmp0,0);
        storecounter.read(checktmp1,1);
        if(codingcountertmp < checktmp0 && codingcountertmp < checktmp1){
        	meta.encodingOK = 1;
        }
    }

    action check_batch(){
    	batch_number.read(batchtmp,(bit<32>)hdr.NC.label);

    	if(batchtmp == 0){
    		meta.deflowID = 0;
    	}
    	else if(batchtmp == 1){
    		meta.deflowID = 1;
    	}
    	else{
    		dropflag = 1;
    	}
    }

    table enstore_packet{
    	key = {
    		meta.enflowID: exact;
    	}
    	actions = {
            enstoreflow0;
            enstoreflow1;
        }
        const entries = {
            0: enstoreflow0();
            1: enstoreflow1();
        }
    }

    table destore_packet{
    	key = {
    		meta.deflowID: exact;
    	}
    	actions = {
            destoreflow0;
            destoreflow1;
        }
        const entries = {
            0: destoreflow0();
            1: destoreflow1();
        }
    }

    table LNCgenerator{
        key = {
            meta.encodingstatus: exact;
        }
        actions = {
        	LNC1;
        	LNC_last;
            NoAction;
        }
        const entries = {
            allencodingnumber-1: LNC_last();
            allencodingnumber: NoAction();
        }
        default_action = LNC1();
    }

    table LNCdecoder{
        key = {
            meta.decodingstatus: exact;
        }
        actions = {
        	DLNC1;
        	DLNC2;
        }
        const entries = {
            0: DLNC1();
            1: DLNC2();
        }
    }

    table NC_init{
    	key = {
    		hdr.ipv4.srcAddr: lpm;
    		hdr.tcp.dstPort: exact;
    	}
        actions = {
            encoding_prim;
        }
        const entries = {
            (0x0a000001,1234) : encoding_prim(0);
            (0x0a000001,1235) : encoding_prim(1);
        }
    }

    table remove_header {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            remove_NC;
        }
    }

    table modifyNCaction {
        key = {
            meta.nextdecode: exact;
        }
        actions = {
        	decoding_prim;
        	noaction_prim;
        }
        default_action = noaction_prim;
    }

    apply {
        if(( hdr.payload.isValid() || hdr.NC.isValid()) && meta.toController != 1){
                if(hdr.NC.isValid() == false && meta.recvReq != 1){
                    hdr.NC.setValid();
                    hdr.ipv4.protocol = 0x90;
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
                    NC_init.apply();
                }
                if(meta.encodingstatus == 0 && meta.decodingstatus == 0){
                	if(hdr.NC.primitive == 2){
                		enstore_packet.apply();
                		encodingcheck();
                	}
                	else if(hdr.NC.primitive == 3){
                		check_batch();
                		if(dropflag == 1){
                			drop();
                		}
                		else{
                			destore_packet.apply();
                			decodingcheck();
                		}
                	}
                    else if(hdr.NC.primitive == 4){
                        hdr.tcp.setValid();
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 20;
                        hdr.payload.setValid();
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen + payloadsize/8;
                        meta.debatch_now = hdr.NC.label;
                    }
                }
                if(meta.encodingOK == 1){
                	LNCgenerator.apply();
                }
                else if(meta.decodingOK == 1){
                	meta.debatch_now = hdr.NC.label;
                    meta.toController = 1;
                    meta.pkt2coeff[15:8] = hdr.NC.coeff1;
                    meta.pkt2coeff[7:0] = hdr.NC.coeff2;
                    codingbuffer0.read(buffertmp0,(bit<32>)meta.debatch_now);
                    meta.pkt1coeff[15:8] = buffertmp0[allpktsize-1:allpktsize-8];
                    meta.pkt1coeff[7:0] = buffertmp0[allpktsize-9:allpktsize-16];
                    recirculate(meta);
                    return;
               	}
                else if(meta.recvReq == 1){
                    if(meta.decodingstatus == 0){
                        meta.debatch_now = hdr.NC.label;
                        meta.pkt1coeff[15:8] = hdr.NC.coeff1;
                        meta.pkt1coeff[7:0] = hdr.NC.coeff2;
                        meta.pkt2coeff[15:8] = hdr.NCextra.excoeff1;
                        meta.pkt2coeff[7:0] = hdr.NCextra.excoeff2;
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 2;
                        hdr.NCextra.setInvalid();
                    }
                    LNCdecoder.apply();
                }
                else{
                	if(hdr.NC.primitive != 0){
                		drop();
                	}
                }
                modifyNCaction.apply();
                if(standard_metadata.instance_type != PKT_INSTANCE_TYPE_EGRESS_CLONE){
                    remove_header.apply();
                }


        }
    }
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

control c_verify_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        if(hdr.NC.isValid()){
            ;
        }
    }
}

control c_compute_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control c_deparser(packet_out packet, in headers_t hdr) {
    apply {
        // Emit headers on the wire in the following order.
        // Only valid headers are emitted.
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.NC);
        packet.emit(hdr.NCextra);
        packet.emit(hdr.tcp);
        packet.emit(hdr.payload);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(c_parser(),
         c_verify_checksum(),
         c_ingress(),
         c_egress(),
         c_compute_checksum(),
         c_deparser()) main;
