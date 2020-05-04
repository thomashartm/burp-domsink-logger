# Burp DOM Sink Logger
[![Build Status Master](https://travis-ci.org/thomashartm/burp-domsink-logger.svg?branch=master)](https://github.com/thomashartm/burp-domsink-logger/tree/master)
[![Build Status Develop](https://travis-ci.org/thomashartm/burp-domsink-logger.svg?branch=develop)](https://github.com/thomashartm/burp-domsink-logger/tree/develop)

The purpose of this plugin is to ease the identification of DOM XSS Sinks and sources.

It injects a trusted types polyfill and default policy into a burp response to 
log all DOM sinks where HTML gets created and directly written into the DOM 
e.g. via innerHTML.

The logging happens on the browser e.g. chrome console.

# Requirements
Requirements to use it:

- Burp v2020.1 Community or Professional
- Recent Browser e.g. Chrome
- Proxy Switcher e.g. FoxyProxy

Requirements to extend or build it:
- Java 11
- Maven
- Idea e.g. IntelliJ or Eclipse

# How to use it
1. Install this plugin via the burp extender e.g. in Burp Community.
2. Open your favorite browser and enable the developer tools via F12
3. Proxy the relevant requests with Burp and your favorite proxy switcher.
4. Enable the plugin. Go to the DomInjector Tab and select enable it via the checkbox.
5. Either select a new taint needle or use the preset one. Inject it into a source e.g. window name or a cookie.
6. If the taint value gets detected in a sink then it will get reported in the browser console.
7. If you want to enable the way more verbose logging then remove the taint needle. This will set the plugin into reporting mode and all usages of createHtml and createScript and createScriptUrl functions will get reported. 


## Trusted Types Default Policy
The plugin uses the trusted types default policy to inject a very tiny piece of logging and taint detection JS code.

The trusted types policy with a name "default", is a special one. 
When an injection sink is passed a string this policy will be implicitly called by the user agent with the string value as the first argument, and the sink name as a second argument.
This can be used to check the string value for taint values coming from a known source, such as our needle value which can be configured in the burp plugin tab.

## Taint value detection vs. logging
Go to the Dom Injector plugin tab to enable and disable the plugin. 
A taint value is set by default.
It is configurable via the input field. 
Save it and reload you page to make any change effective.

If you clear the field, then taint detection gets disabled and generic logging enabled. 



# How to build and install

Run maven  to build the plugin.  
    
    mvn clean install 
    
Go to the Burp Extender tab, 
click on "Add" and select the plugin from the target folder.

# Contributions
Feel free to raise feature requests or report bugs as a github issue.
Any contributions are welcome, 
just create and issue and raise a pull request.

# License
All contents of this repository as well as the 
compiled output fall under the attached GNU GPL v3 license.