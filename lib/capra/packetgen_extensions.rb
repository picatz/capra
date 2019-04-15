module PacketGen
  class Packet
    def ftp?
      return false unless self.is? 'TCP'
      self.tcp.dport == 21 || self.tcp.sport == 21
    end

    def ssh?
      return false unless self.is? 'TCP'
      self.tcp.dport == 22 || self.tcp.sport == 22
    end
   
    def icmp?
      self.is? 'ICMP'
    end

    def http?
      return false unless self.is? 'TCP'
      self.is? 'HTTP::Request' or self.is? 'HTTP::Response'
    end
    
    def https?
      return false unless self.is? 'TCP'
      self.tcp.dport == 443 || self.tcp.sport == 443 
    end

    def telnet?
      return false unless self.is? 'TCP'
      self.tcp.dport == 23 || self.tcp.sport == 23
    end
  end

  module Header
    class TCP
      def port?(int)
        self.dport == int || self.dport == int
      end
    end
    
    class DNS
      def queries
        return [] unless self.query?
        packet.dns.qd.map { |q| q.name.chop! }
      end

      def responses
        return [] unless self.response?
        packet.dns.an.map { |a| a.human_rdata }
      end
    end

    class IP
      def internal_communication_only?
        PRIVATE_IPS.any? { |private_ip| private_ip.include?(self.src) } and PRIVATE_IPS.any? { |private_ip| private_ip.include?(self.dst) }
      end

      def external_communication?
        !internal_communication_only?
      end

      def internal_destination?
        PRIVATE_IPS.any? { |private_ip| private_ip.include?(self.dst) }
      end
      
      def external_destination?
        !internal_destination?
      end

      def internal_source?
        PRIVATE_IPS.any? { |private_ip| private_ip.include?(self.src) }
      end

      def external_source?
        !internal_source? 
      end

      def within_subnet?(cidr)
        subnet = IPAddr.new(cidr)
        subnet.include?(self.src) or subnet.include?(self.dst)
      end
      
      def from_subnet?(cidr)
        subnet = IPAddr.new(cidr)
        subnet.include?(self.src)
      end
      
      def from_subnets?(cidrs)
        cidrs.map { IPAddr.new(cidr) }.include?(self.src)
      end
      
      def to_subnet?(cidr)
        subnet = IPAddr.new(cidr)
        subnet.include?(self.dst)
      end

      def to_subnets?(cidr)
        cidrs.map { IPAddr.new(cidr) }.include?(self.dst)
      end
    end

    class ICMP
      def echo_reply?
        self.type == 0
      end

      def destination_unreachable?
        self.type == 3
      end

      def redirect?
        self.type == 5
      end

      def echo?
        self.type == 8
      end

      def router_advertisement?
        self.type == 9
      end

      def router_solicitation?
        self.type == 10
      end
    end
  end
end

