# ActiveEvent v1.0 - Burp Suite Etension
# Created by Tiago Ferreira - Security Engineering (tiago at blazeinfosec dot com)
# Blaze Information Security - http://www.blazeinfosec.com/
#
# Description: ActiveEvent is a plugin that will continuously monitor the Burp vulnerability scanner
# looking for new security issues. As soon as the scanner reports new vulnerabilities, the plugin will 
# generate an Splunk Event directly into it's management interface using the Http Event Collector.
#
# Tip: To avoid memory issues using JRuby plugin, please run Burp Suite with the following syntax: 
# java -XX:MaxPermSize=1G -jar burp.jar

require 'java'
require 'uri'
require 'json'
require 'net/https'

java_import 'burp.IBurpExtender'
java_import 'burp.IScanIssue'
java_import 'burp.IScannerListener'
 
PLUGIN_NAME = 'ActiveEvent'

class Connector

  HTTP_METHODS = {
    :get     =>  Net::HTTP::Get,
    :post    =>  Net::HTTP::Post,
    :put     =>  Net::HTTP::Put,
    :delete  =>  Net::HTTP::Delete
  }

  attr_accessor :uri, :api_key

  def initialize(uri, api_key)
    @uri = URI.parse(uri)
    @api_key = api_key
  end

  def request(method, parameters)
    begin
      connect = Net::HTTP.new(@uri.host, @uri.port)
      connect.use_ssl = true
      connect.verify_mode = OpenSSL::SSL::VERIFY_NONE

      request = HTTP_METHODS[method].new(@uri.path)
      request.add_field("Authorization", " Splunk #{@api_key}")
      request.body = parameters
      response =  connect.request(request)
        
    rescue Exception => e
        puts "\t[-] - Something went wrong with your request: #{e}"
        exit
    end

    return response
  end

  def check_token
    valid = self.request(:post, "")
    if valid.code == '403'
      puts "[-] - Authentication error, please verify your access token."
      return false 
    else
      return true
    end
  end
end

class BurpExtender
  include IBurpExtender, IScanIssue, IScannerListener

  def registerExtenderCallbacks(callbacks)
  	# keep a reference to  our registerExtenderCallbacks
    @callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName(PLUGIN_NAME)

    # obtain the user parameters
    @config = get_parameters

    # register scanner listener
    puts "[*] #{PLUGIN_NAME} plugin loaded successfully"
    puts "[*] - Waiting for scanner findings ...\n\n"
    callbacks.registerScannerListener(self)

  end

  def get_parameters
    cmd = @callbacks.getCommandLineArguments()
    if cmd.size != 3
      puts %q{
              [-] Before executing this plugin you need to call Burp Suite
              from the command line and specify the Splunk IP address, port 
              and a valid SPLUNK API KEY, respectively. 

              ex: java -XX:MaxPermSize=1G -jar Burp.jar 127.0.0.1 8088 'xxx-yyy'
            }
    else
      splunk_config = {
          :SPLUNK_URL     => "https://#{cmd[0]}:#{cmd[1]}/services/collector/event",
          :SPLUNK_API_KEY => cmd[2]
      }
    end

    return splunk_config
  end

  # This method is invoked whenever Burp Scanner discovers a new, unique issue.
  def newScanIssue(issue)
    event = {
        'details'        => issue.getIssueDetail,
        'vulnerability'  => issue.issueName,
        'severity'       => issue.severity,
        'url'            => issue.url.to_s,
        'port'           => issue.port,
        'host'           => issue.host
    }
    send_event(event) 
  end

  def send_event(event)
    connection = Connector.new(@config[:SPLUNK_URL], @config[:SPLUNK_API_KEY])
    if connection.check_token
      connection.request(:post, "{\"event\": #{event.to_json}}") 
      puts "[+] - Vulnerability sent to Splunk: #{event['vulnerability']}"
    end
  end
end