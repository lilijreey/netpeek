#!/usr/bin/env ruby
require 'socket'
require 'bindata'

S = Socket

class MacAddr < BinData::Primitive
  array :octets, type: :uint8, initial_length: 6

  def set(val)
    self.octets = val.split(/\./).collect(&:to_i)
  end

  def get
    self.octets.collect { |octet| "%02x" % octet }.join(":")
  end
end

class IPAddr < BinData::Primitive
  array :octets, type: :uint8, initial_length: 4

  def set(val)
    self.octets = val.split(/\./).collect(&:to_i)
  end

  def get
    self.octets.collect { |octet| "%d" % octet }.join(".")
  end
end
# IP Protocol Data Unit
class IpHead < BinData::Record
=begin Head 20B
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Version|  IHL  |Type of Service|          Total Length         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Identification        |Flags|      Fragment Offset    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Time to Live |    Protocol   |         Header Checksum       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Source Address                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Destination Address                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=end

  endian :big

  bit4   :version, asserted_value: 4
  bit4   :header_length
  uint8  :tos
  uint16 :total_length
  uint16 :ident
  bit3   :flags
  bit13  :frag_offset
  uint8  :ttl
  uint8  :protocol
  uint16 :checksum
  ip_addr :src_addr
  ip_addr :dest_addr
  string :options, read_length: :options_length_in_bytes
  #buffer :payload, length: :payload_length_in_bytes do
  #  choice :payload, selection: :protocol do
  #    tcp_pdu  6
  #    udp_pdu 17
  #    rest    :default
  #  end
  #end

  def header_length_in_bytes
    header_length * 4
  end

  def options_length_in_bytes
    header_length_in_bytes - options.rel_offset
  end

  def payload_length_in_bytes
    total_length - header_length_in_bytes
  end
end

class TcpHead < BinData::Record
=begin Head 20B
  0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  head |       |C|E|U|A|P|R|S|F|                               |
  | length| Resv  |w|C|R|C|S|S|Y|I|            Window             |
  |       |       |R|E|G|K|H|T|N|N|                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |         Urgent Pointer        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             data                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=end
	endian :big

  uint16 :src_port
  uint16 :dst_port
  # 接收数据只会改变自己的seq
  # 发送数据只会改变自己的ack
  uint32 :seq #对于发送方一个标记,用于指导接收方下一次发包时ack的基准
  uint32 :ack #对于发送方 期待下一次收到的包的seq数, 对于接收方
  bit4   :head_len
  bit4   :resv
  bit1   :f_cwr
  bit1   :f_ece
  bit1   :f_urg
  bit1   :f_ack
  bit1   :f_psh
  bit1   :f_rst
  bit1   :f_syn
  bit1   :f_fin
  uint16 :window
  uint16 :checksum
  uint16 :urg_ptr
  string :options, read_length: :options_length_in_bytes

  def header_length_in_bytes
   head_len * 4
  end

	def options_length_in_bytes
		(head_len- 5) * 4
	end
end

class UdpHead < BinData::Record
  endian :big

  uint16 :src_port
  uint16 :dst_port
  uint16 :len
  uint16 :checksum
  rest   :payload
end
 
#EE Raw socket see raw(7)
# limits:
#  1. only recv incoming packets
#
def make_ip_tcp_raw_socket
  return Socket.new(S::AF_INET, S::SOCK_RAW, S::IPPROTO_TCP)
end

def make_ip_udp_raw_socket
  return Socket.new(S::AF_INET, S::SOCK_RAW, S::IPPROTO_UDP)
end

#EE Packet socket see packet(7)
#can get all 2 layer in-and-out traffic

def htons(n)
  [n].pack("S>")
    .unpack("S")[0]
end

def make_2layer_raw_socket
  eth_p_all = htons(0x003) #define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
  return Socket.new(S::AF_PACKET, S::SOCK_RAW, 768)
end



def peek_tcp
  s = make_ip_tcp_raw_socket
  rxCnt = 0
  rxBytes =0
  while true
    data = s.recv(65535)

    #IP
    ipHead = IpHead.read(data)
    rxCnt+= 1
    rxBytes += data.length
    printf("Recv pkgLen:%d rxCnt:%d rx-size:%dK:%dM\n", data.length, rxCnt, rxBytes>>10, rxBytes>>20)
    printf("IP HEAD %d:%s\n", ipHead.header_length_in_bytes, ipHead)

    #TCP
    data = data[ipHead.header_length_in_bytes..-1]
    tcpHead = TcpHead.read(data)
    printf("TCP HEAD %d:%s\n", tcpHead.header_length_in_bytes, tcpHead)
    
    #App
    data = data[tcpHead.header_length_in_bytes..-1]
    printf("payload:%d %s\n", data.length, data)
  end

end

def peek_udp
  s = make_ip_udp_raw_socket
  rxCnt = 0
  rxBytes =0
  while true
    data = s.recv(65535)
    rxCnt += 1
    rxBytes += data.length
    printf("Recv pkgLen:%d rxCnt:%d rxSize:%dK: %s\n", data.length, rxCnt, rxBytes>>10, data)
  end
end

# Ethernet Frame - NOTE only ipv4 is supported
class EtherHead < BinData::Record
=begin
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Ethernet destination address (first 32 bits)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Ethernet source address (last 32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Type code              |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
=end
  IPV4 = 0x0800

  endian :big
  mac_addr :dst
  mac_addr :src
  uint16   :ether_type
  #string   :payload
  #choice   :payload, selection: :ether_type do
  #  ip_pdu IPV4
  #  rest   :default
  #end
end


def peek_l2
  s = make_2layer_raw_socket
  rxCnt = 0
  rxBytes =0
  while true
    data = s.recv(65535)
    rxCnt += 1
    rxBytes += data.length
    ethHead = EtherHead.read(data)
    printf("Recv pkgLen:%d rxCnt:%d rxSize:%dK: %s\n", data.length, rxCnt, rxBytes>>10, ethHead)
  end

end

peek_l2
