require "packetgen"
require "ipaddr"
require "fileutils"
require "command_lion"
require "capra/version"
require "capra/private_ips"
require "capra/packetgen_extensions"
require "capra/snort_rule_parser"
require "capra/engine"
require "capra/version"

require "pry"

module Capra
  class Error < StandardError; end

  def self.run_cli!
    CommandLion::App.run do
      name "Capra"
      version Capra::VERSION
      description "Intrusion Detection System"

      command :init do
        description "create a base Caprafile in the current working directory"

        action do
          if File.exists?("Caprafile")
            puts "error: Caprafile already exists!"
            exit 1
          end
          File.open("Caprafile", 'w') do |file| 
            file.puts '#!/usr/bin/env ruby'
            file.puts
            file.puts "interface = '#{Interfacez.default}'"
            file.puts
            file.puts "# your rules go here"
          end
        end
      end

      command :start do
        description "start the engine"

        default "Caprafile"

        action do
          unless File.exists?(argument)
            puts "error: cannot find #{argument} in the current directory"
            puts
            puts "hint: run `capra init` to create a base Caprafile"
            exit 1
          end

          Capra::Engine.new(file: argument)
        end
      end

      # $ capra convert 'alert tcp any any -> any 21 (msg:"ftp")'
      # rule 'TCP' do |packet|
      #   next unless packet.tcp.dport == 21
      #   alert "ftp"
      # end
      command :convert do
        description "Convert Snort rule(s) to Caprafile syntax"

        type :string

        action do
          if File.file?(argument)
            File.foreach(argument) do |line|
              line = line.strip
              next if line.empty?

              Capra::SnortRuleParser.convert(line)
            end
          else
            Capra::SnortRuleParser.convert(argument)
          end
        end
      end
    end
  end
end
