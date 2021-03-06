module Spcap
  class Scopy < Stream
    CURRENT_OUT_FILENAME = 'pcapcopy.tmp'
    FILENAME_EXTENTION = '.pcap'
    def initialize(istream,opt = {})
      @tmpname = CURRENT_OUT_FILENAME
      @wpath = opt[:wpath] || ''
      @prefix = opt[:prefix] || ''
      @limit = opt[:limit] || 10000
      @counter = 0
      @ostream = new_file
      super(istream)
      packing = @unpack_16 + @unpack_16 + @unpack_32 + @unpack_32 + @unpack_32 + @unpack_32
      @header = @magic_number + [@major_version, @minor_version, 0, 0, @snapshot_length, 
        @linklayer_header_type].pack(packing)
    end
    
    def read(size)
      buf = @istream.read(size)
      @ostream.write(buf)
      return buf
    end
    
    def new_file ; File.new(File.expand_path(backup_name,@wpath),"w") ; end
    
    def backup_name
      @prefix + Time.now.strftime("%Y%m%d%H%M%S%6N") + FILENAME_EXTENTION
    end

    def switch_out
      @ostream.close
      @ostream = new_file
      @ostream.write(@header)
    end
    
    def finalize
      @ostream.close
    end
    
    def next
      pkt = super
      @counter += 1
        if @counter == @limit
          switch_out
          @counter = 0
        end
      return pkt
    end
  end
end