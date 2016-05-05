## ActiveEvent Burp Plugin

ActiveEvent is a Burp plugin that will continuously monitor Burp scanner looking for 
new security issues. As soon as the scanner reports new vulnerabilities, the plugin 
will generate an Splunk Event directly into its management interface using the
Http Event Collector.

# Install 

```
git clone https://github.com/blazeinfosec/ActiveEvent.git
```
To use Ruby extensions, it is necessary to download JRuby and configure the JRuby
enviroment. 

```
export JRUBY_HOME=/usr/local/bin/ruby (path to your ruby binary)
```

## Load the extension 

To run this plugin you need to call Burp Suite from the command line and specify the Splunk IP address, TCP port and a valid SPLUNK API KEY, respectively. 

```
java -XX:MaxPermSize=1G -jar burp.jar 127.0.0.1 8088 'xxx-yyy-'
```
As soon as Burp starts, go to Extender Tab > Options> Ruby Enviroment and specify the path to your Jruby jar file. Next in the Extender Tab > Extensions > Add, choose Ruby as an extension type and the path to 
this plugin. 

You should see the plugin output:

```
[*] ActiveEvent plugin loaded successfully
[*] - Waiting for scanner findings ...

```

## Resources

Burp Extender documentation
* [Burp Extender Documentation] (https://portswigger.net/burp/help/extender.html)

## Author

* **Tiago Ferreira** - tiago at blazeinfosec dot com

## License 

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details
