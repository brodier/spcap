module Spcap
  class IPPacket < Packet
    attr_reader :src,:dst,:ip_hlen,:ip_len
    
    def initialize(time,data,len,datalink)
      super(time,data,len,datalink)
      @src = IPAddress.new(@raw_data[12,4])
      @dst = IPAddress.new(data[16,4])
      @ip_hlen = @raw_data.getbyte(0) & 0x0F
      @ip_len = @raw_data[2,2].unpack("n").first
      
    end
    
    # Return data part as String.
    def ip_data
      @raw_data[ip_hlen*4,self.caplen-ip_hlen*4]
    end
    
    # 
    # Return the value of 3-bits IP flag field.
    def ip_flags
      @raw_data.getbyte(6) & 0xE0
    end
    
    # Return true if Don't Fragment bit is set.
    def ip_df?
      (@raw_data.getbyte(6) & 0x40) == 0x40
    end
    
    # Return true if More Fragment bit is set.
    def ip_mf?
      (self.raw_data.getbyte(6) & 0x20) == 0x20
    end
    
    # Return destination IP address as IPAddress.
    def ip_dst
      @dst
    end
    # Return source IP address as IPAddress.
    def ip_src
      @src
    end
    
    # Return identification.
    def ip_id
      @raw_data[4,4]
    end
    
    # Return fragment offset.
    def ip_off
      @raw_data[6,2].unpack("n").first & 0xFFF
    end
    
    
    # Return the value of protocol field.
    def ip_proto
      @raw_data.getbyte(9)
    end
    
    # Return the value of checksum field.
    def ip_sum
      @raw_data[10,2].unpack("n").fisrt
    end

    
    # Return the value of TOS field.
    def ip_tos
      # TODO
    end
    
    
    # Return TTL.
    def ip_ttl
      @raw_data.getbyte(8)
    end
    
    
    # Return IP version.
    def ip_ver
      ( @raw_data.getbyte(0) & 0xF0 ) / 16
    end
    
    # Return string representation.
    def to_s
      "TODO" # TODO
    end
    
  end
end