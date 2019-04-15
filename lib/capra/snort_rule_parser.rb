module Capra 
    module SnortRuleParser
      def self.parse(rule)
        # alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"FTP MDTM overflow attempt"; flow:to_server,established; content:"MDTM"; nocase; isdataat:100,relative; pcre:"/^MDTM\s[^\n]{100}/smi"; reference:bugtraq,9751; reference:cve,2001-1021; reference:cve,2004-0330; reference:nessus,12080; classtype:attempted-admin; sid:2546; rev:5;)
        rule_parts = rule.split
  
        rule_options = {} 
 
        rule_parts[7..].join(" ").sub("(",'').sub(")",'').split(";").map { |opt| opt.split(":").map { |val| val.gsub('"', '') }}.each do |k, v|
          k = k.strip
  
          if rule_options[k]
            rule_options[k] << v
          else
            rule_options[k] = [v]
          end
        end
  
        {
          action: rule_parts[0],
          protocol: rule_parts[1],
          source_ip: rule_parts[2],
          source_port: rule_parts[3],
          direction: rule_parts[4], # almost always -> unless you're crazy?
          destination_ip: rule_parts[5],
          destination_port: rule_parts[6],     
          options: rule_options
        }
      end
  
      def self.convert(rule)
        parsed_rule = self.parse(rule)
        puts "rule '#{parsed_rule[:protocol].upcase}' do |packet|"
        unless parsed_rule[:source_ip] == "any"
          if parsed_rule[:source_ip] == "$EXTERNAL_NET" # might want to check direction too?
            puts "\tnext unless packet.ip.external_source?"
          elsif parsed_rule[:source_ip][0] == "["
            puts "\tnext unless packet.ip.from_subnets?(#{parsed_rule[:source_ip].sub("[","").sub("]","").split(",").inspect})"
          else
            puts "\tnext unless packet.ip.src == '#{parsed_rule[:source_ip]}'"
          end
        end
        unless parsed_rule[:source_port] == "any"
          puts "\tnext unless packet.#{parsed_rule[:protocol]}.sport == #{parsed_rule[:source_port]}"
        end
        unless parsed_rule[:destination_ip] == "any"
          if parsed_rule[:destination_ip] == "$HOME_NET"
            puts "\tnext unless packet.ip.internal_destination?"
          elsif parsed_rule[:source_ip][0] == "["
            parsed_rule[:source_ip].sub("[","").sub("]","").split(",").each do |cidr|
              puts "\tnext unless packet.ip.to_subnets?(#{cidr})"
            end
          else
            puts "\tnext unless packet.ip.dst == '#{parsed_rule[:destination_ip]}'"
          end
        end
        unless parsed_rule[:destination_port] == "any"
          puts "\tnext unless packet.#{parsed_rule[:protocol]}.dport == #{parsed_rule[:destination_port]}"
        end
        # TODO: need to support mixed string and byte matching, even though it's insane
        if parsed_rule[:options]["content"]
          parsed_rule[:options]["content"].each do |content|
            if content[0] == "|" and content[-1] == "|"
              puts "\tnext packet.body.unpack('H*').first.include?(\"#{content.gsub("|","").split.join}\")"
            else
              puts "\tnext unless packet.body.include?(\"#{content}\")"
            end  
          end
          #puts "\tnext unless packet.body.include?(\"#{parsed_rule[:options]["content"]}\")"  
        end
        if parsed_rule[:options]["pcre"]
          parsed_rule[:options]["pcre"].each do |pcre|
            regex, regex_ops = pcre.split("/")[1..]
            regex_ops_value = regex_ops.split('').map do |str|
              case str
              when "i"
                Regexp::IGNORECASE
              when "m"
                Regexp::MULTILINE
              when "x"
                Regexp::EXTENDED
              else
                0
              end
            end.sum
            puts "\tnext unless packet.body.match(Regexp.new('#{regex}', #{regex_ops_value}))"  
          end
        end
        if parsed_rule[:options]['flags']
          parsed_rule[:options]['flags'].each do |flag_opt|
            flag_opt.split('').each do |flag|
              case flag
              when 'F' #fin
                puts "\tnext unless packet.tcp.flag_fin?"
              when 'S' #syn
                puts "\tnext unless packet.tcp.flag_syn?"
              when 'R' #rst
                puts "\tnext unless packet.tcp.flag_rst?"
              when 'P' #psh
                puts "\tnext unless packet.tcp.flag_psh?"
              when 'A' #ack
                puts "\tnext unless packet.tcp.flag_ack?"
              when 'U' #urg
                puts "\tnext unless packet.tcp.flag_urg?"
              end
            end
          end
        end
        # alert probably needs to be the last thing in the rule for it to work properly in this case
        if parsed_rule[:options]["msg"]
          puts "\talert \"#{parsed_rule[:options]["msg"].first}\""
        end
        puts "end"
      end
    end
  end
  