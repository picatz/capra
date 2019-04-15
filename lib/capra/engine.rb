module Capra
    class Engine 
      attr_accessor :interface
      attr_accessor :rules
  
      def initialize(file: nil, &block)
        @interface = Interfacez.default
        @rules     = {}
        if file
          instance_eval File.read(file)
        else
          instance_eval &block
        end
        start!
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
  
      def email(recpt)
        puts "Sending email!"
      end
  
      def start!
        PacketGen.capture(iface: @interface) do |packet|
          @rules.each do |header, blocks|
            next unless packet.is? header
            blocks.each do |block|
              block.call(packet)
            end
          end
        end
      end
    end
  end
  