const reportUnsafeOperation = (s, sink) =>{
    // using warn as it creates a nice warning message with a stacktrace showing us where it came from
    console.warn("TT-Policy Default: ", s, " at ", sink);
};

trustedTypes.createPolicy('default',{
    createHTML: (s, sink) => {
        reportUnsafeOperation(s, sink);
        return s;
    },
    createScript: (s, sink) => {
        reportUnsafeOperation(s, sink);
        return s;
    },
    createScriptURL: (s, sink) =>{
        reportUnsafeOperation(s, sink);
        return s;
    }
},true);