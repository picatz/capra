# frozen_string_literal: true

module PacketGen
  class Packet
    def ftp?
      return false unless is? 'TCP'

      tcp.dport == 21 || tcp.sport == 21
    end

    def ssh?
      return false unless is? 'TCP'

      tcp.dport == 22 || tcp.sport == 22
    end

    def icmp?
      is? 'ICMP'
    end

    def http?
      return false unless is? 'TCP'

      is?('HTTP::Request') || is?('HTTP::Response')
    end

    def https?
      return false unless is? 'TCP'

      tcp.dport == 443 || tcp.sport == 443
    end

    def telnet?
      return false unless is? 'TCP'

      tcp.dport == 23 || tcp.sport == 23
    end

    def dns?
      return true if is? 'DNS'
    end

    def ip?
      return true if is? 'IP'
    end

    def arp?
      return true if is? 'ARP'
    end
  end

  module Header
    class TCP
      def port?(int)
        dport == int || dport == int
      end
    end

    class DNS
      def queries
        return [] unless query? || response?

        packet.dns.qd.map { |q| q.name.chop! }
      end

      def responses
        return {} unless response?

        info = {}
        packet.dns.an.map do |a|
          name = a.name.chop!
          if info[name]
            info[name] << a.human_rdata
          else
            info[name] = [a.human_rdata]
          end
        end
        info
      end
    end

    class IP
      def internal_communication_only?
        PRIVATE_IPS.any? { |private_ip| private_ip.include?(src) } && PRIVATE_IPS.any? { |private_ip| private_ip.include?(dst) }
      end

      def external_communication?
        !internal_communication_only?
      end

      def internal_destination?
        PRIVATE_IPS.any? { |private_ip| private_ip.include?(dst) }
      end

      def external_destination?
        !internal_destination?
      end

      def internal_source?
        PRIVATE_IPS.any? { |private_ip| private_ip.include?(src) }
      end

      def external_source?
        !internal_source?
      end

      def within_subnet?(cidr)
        subnet = IPAddr.new(cidr)
        subnet.include?(src) || subnet.include?(dst)
      end

      def from_subnet?(cidr)
        subnet = IPAddr.new(cidr)
        subnet.include?(src)
      end

      def from_subnets?(cidrs)
        cidrs.map { IPAddr.new(cidr) }.include?(src)
      end

      def to_subnet?(cidr)
        subnet = IPAddr.new(cidr)
        subnet.include?(dst)
      end

      def to_subnets?(cidrs)
        cidrs.map { IPAddr.new(cidr) }.include?(dst)
      end
    end

    class ICMP
      def echo_reply?
        type == 0
      end

      def destination_unreachable?
        type == 3
      end

      def redirect?
        type == 5
      end

      def echo?
        type == 8
      end

      def router_advertisement?
        type == 9
      end

      def router_solicitation?
        type == 10
      end
    end
  end
end
