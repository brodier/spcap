module Spcap
  TCP_FLAGS  = "UAPRSF"
  class TCPPacket < IPPacket
    def initialize(time,data,len,datalink)
      super(time,data,len,datalink)
    end
    
    def channel ; [[src,sport],[dst,dport]] ; end
    def full_session ; channel.sort ; end
    def session ; full_session.hash ; end    
    def direction ; full_session == channel ; end
    
    # Return acknowledgement number.
    def tcp_ack ; ip_data[8,4].unpack("N").first ; end
    
    # Return data part as String.
    def tcp_data ; ip_data[tcp_off*4,tcp_data_len] ; end
    
    # Return length of data part.
    def tcp_data_len ; ip_len - ( ip_hlen * 4 ) - (tcp_hlen * 4) ; end
    
    # Return destination port number.
    def tcp_sport ; ip_data[0,2].unpack("n").first ; end
    def sport ; tcp_sport ; end

    # Return destination port number.
    def tcp_dport ; ip_data[2,2].unpack("n").first ; end
    def dport ; tcp_dport ; end
    
    # Return the value of 6-bits flag field.
    def tcp_flags ; ( ip_data.getbyte(13) & 0x3F ) ; end

    # Return the value of 6-bits flag field as string like ".A...F".
    def tcp_flags_s
        ip_data[13].unpack("B*").first[2,6].
          chars.zip(TCP_FLAGS.chars).collect { |flag,flag_s|
            (flag == '0' ? '.' : flag_s)
          }.join
    end

    # Return true if flag is set.
    def tcp_fin? ; flag?(7) ; end
    def tcp_syn? ; flag?(6) ; end
    def tcp_rst? ; flag?(5) ; end
    def tcp_psh? ; flag?(4) ; end
    def tcp_ack? ; flag?(3) ; end
    def tcp_urg? ; flag?(2) ; end
    
    # Return TCP data offset (header length). (Unit: 4-octets)
    def tcp_hlen ;  ( ( ip_data.getbyte(12) & 0XF0) / 16 ) ; end
    def tcp_off ; tcp_hlen ; end
    
    # Return sequence number.
    def tcp_seq ; ( ip_data[4,4].unpack("N").first ) ; end

    # Return the value of checksum field.
    def tcp_sum ; ( ip_data[16,2].unpack("n").first ) ; end

    # Return urgent pointer.
    def tcp_urp ; ( ip_data[18,2].unpack("n").first ) ; end

    # Return window size.
    def tcp_win ; ( ip_data[14,2].unpack("n").first ) ; end
        
    # Return string representation.
    def to_s ; "TODO" ; end

    private 
    def flag?(i) ; ip_data[13].unpack("B*").first[i] == '1'; end

  end
end
