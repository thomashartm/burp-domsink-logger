# Burp DOM Sink Logger
[![Build Status Master](https://travis-ci.org/thomashartm/burp-domsink-logger.svg?branch=master)](https://github.com/thomashartm/burp-domsink-logger/tree/master)
[![Build Status Develop](https://travis-ci.org/thomashartm/burp-domsink-logger.svg?branch=develop)](https://github.com/thomashartm/burp-domsink-logger/tree/develop)

The purpose of this plugin is to ease the identification of DOM XSS Sinks and sources.
Injects a trusted types policy into a burp response to 
log all DOM sinks where HTML is created and directly written into the DOM e.g. via innerHTML.

## Trusted Types Default Policy
The trusted types policy with a name "default", is a special one. 
When an injection sink is passed a string this policy will be implicitly called by the user agent with the string value as the first argument, and the sink name as a second argument.
This can be used to check the string value for previously tained parameter coming from a known source.


# How to build and install

Run maven  to build the plugin.  
    
    mvn clean install 
    
Go to the Burp Extender tab, 
click on "Add" and select the plugin from the target folder.