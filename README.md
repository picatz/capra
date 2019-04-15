# Capra

Capra is a powerful Intrusion Detection System. 

## Installation

```console
$ gem install capra
```

## Usage

To start, we will create a base `Caprafile` using the `init` sub-command:

```console
$ capra init
```
By default, it will find your default network interface, which will work in most cases. You can also specify the interface to use:

```console
$ capra init --interface eth0
```

A default `Caprafile` looks like this:

```ruby
#!/usr/bin/env ruby

interface = "eth0"

# your rules go here
```

You can convert snort rules to `Caprafile` syntax:

```console
$ capra convert 'alert tcp any any -> any 21 (msg:"ftp")'
rule 'TCP' do |packet|
        next unless packet.tcp.dport == 21
        alert "ftp"
end
```

You can append the converted snort rule output to the `Caprafile` like so:

```
$ capra convert 'alert tcp any any -> any 21 (msg:"ftp")' >> Caprafile
```

You can also covert snort rules from a given file:

```
$ capra convert snort_rules.txt
...
```

Starting the engine is a simple as:

```
$ capra start
...
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/picatz/capra. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Capra project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/picatz/capra/blob/master/CODE_OF_CONDUCT.md).
