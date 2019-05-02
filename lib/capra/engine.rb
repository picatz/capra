# frozen_string_literal: true

module Capra
  class Engine
    attr_accessor :interface
    attr_accessor :rules

    def initialize(file: nil, &block)
      default_interface
      @rules = {}
      if file
        instance_eval File.read(file)
      else
        instance_eval &block
      end
      start!
    end

    def interface(iface)
      @interface = iface
    end

    def default_interface
      @interface = Interfacez.default
    end

    def pcap(file)
      @pcap = file
    end

    def save_to(file)
      @save_to = file
    end

    def rule(type, description: nil, reference: nil, &block)
      if @rules[type]
        @rules[type] << block
      else
        @rules[type] = [block]
      end
    end

    def alert(mesg)
      puts mesg
    end

    def email(_recpt)
      puts 'Sending email!'
    end

    def save(packet)
      @save_to = 'capra-save-' + Time.now.utc.to_s.split(' ').join('-') + '.pcapng' if @save_to.nil?

      pf = PacketGen::PcapNG::File.new
      pf.array_to_file [packet]
      pf.to_f(@save_to, append: true)
    end

    def start!
      if @pcap
        read_pcap_file(@pcap) do |packet|
          @rules.each do |header, blocks|
            next unless header == 'ANY' || packet.is?(header)

            blocks.each do |block|
              block.call(packet)
            end
          end
        end
      else
        PacketGen.capture(iface: @interface) do |packet|
          @rules.each do |header, blocks|
            next unless header == 'ANY' || packet.is?(header)

            blocks.each do |block|
              block.call(packet)
            end
          end
        end
      end
    end

    private

    def read_pcap_file(filename)
      PcapNG::File.new.read_packets(filename) do |packet|
        yield packet
      end
    rescue StandardError
      PCAPRUB::Pcap.open_offline(filename).each_packet do |packet|
        next unless (packet = PacketGen.parse(packet.to_s))

        yield packet
      end
    end
  end
end
