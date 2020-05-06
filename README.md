# Burp DOM Sink Logger
[![Build Status Master](https://travis-ci.org/thomashartm/burp-domsink-logger.svg?branch=master)](https://github.com/thomashartm/burp-domsink-logger/tree/master)
[![Build Status Develop](https://travis-ci.org/thomashartm/burp-domsink-logger.svg?branch=develop)](https://github.com/thomashartm/burp-domsink-logger/tree/develop)

The purpose of this plugin is to ease the identification of DOM XSS Sinks and sources.

It injects a trusted types polyfill and default policy into a burp response to 
log all DOM sinks where HTML gets created and directly written into the DOM 
e.g. via innerHTML.

The logging happens inside the browser's webconsole e.g. Chrome's console.

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
4. Enable the plugin. Go to the DomInjector Tab and select the "Enable" checkbox.
6. The plugin supports t2o operation modes:
6.1 Logging Mode which basically logs all injection sinks which are considered unsafe
6.2 Taint mode which logs a sink only if the configured taint value get's reflected

## Taint value detection vs. logging
Go to the Dom Injector plugin tab to enable and disable the plugin. 
A taint value is set by default.
It is configurable via the input field. 
Save it and reload you page to make any change effective.

### Logging Mode
This is the default setting where the plugin's taint mod eis disabled. 
All usages of createHtml and createScript and createScriptUrl functions will be reported in the browsers webconsole.

### Taint Mode
1. Enable the taint mode via the checkbox.
2. Either select a new taint needle or use the preset one. 
3. Inject it into a source e.g. window name or a cookie.
4. If the taint value gets detected in a sink then it will get reported in the browser console.
6. If you want to re-enable the way more verbose logging then just untick the operations mode checkbox again.
  
## Important hint
The plugin is an interceptor which injects some javascript into the response before it get's to the browser.
The injected code does not communicate back to Burp.
Any output by injected code gets written into the browser console and nowhere else.

## Trusted Types 
Trusted Types are a browser API which helps to write, review and maintain applications free of DOM XSS vulnerabilities. 
That's at least basically the main goal.
It makes critical or dangerous web API functions more secure by instructing user agents to restrict the 
usage of this known DOM XSS sinks to a predefined set of functions that only accepts non-spoofable, typed values in place of strings. 
See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types

### What is the benefit of using them to identify potential sinks 
The trusted types API provides a default fallback for cases where there is no specific "trusted types" function. 
This default gets triggered when potential unsafe writes e.g. html to the DOM.
That behaviour makes TTs pretty attractive for using the API in a security review, to get an overview of potential dom sinks:
It is easy pretty stable, simple to prepare and easy to inject through a proxy and that's exactly what the plugin is doing. 

### Browser Support
Trusted Types are supported in Chrome 83 and there is a polyfill available for other browsers.
The plugin is using currently injecting ES5 polyfill.

### Trusted Types Default Policy
The plugin uses the trusted types default policy to inject a very tiny piece of logging and taint detection JS code.

The trusted types policy with a name "default", is a special one. 
When an injection sink is passed a string this policy will be implicitly called by the user agent with the string value as the first argument, and the sink name as a second argument.
This can be used to check the string value for taint values coming from a known source, such as our needle value which can be configured in the burp plugin tab.




# How to build and install

Run maven  to build the plugin.  
    
    mvn clean install 
    
Go to the Burp Extender tab, 
click on "Add" and select the plugin from the target folder.

# Contributions
Feel free to raise feature requests or report bugs as a github issue.
Any contributions are welcome.
Please follow the linked contribution guidelines
https://gist.github.com/MarcDiethelm/7303312

# License
All contents of this repository as well as the 
compiled output fall under the attached GNU GPL v3 license.
