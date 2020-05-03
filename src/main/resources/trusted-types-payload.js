const TAINT_VALUE = "";
const checkTaint = false;

const reportUnsafeOperation = (s, sink) =>{
    // using warn as it creates a nice warning message with a stacktrace showing us where it came from
    console.warn("TT-Policy Default: ", s, " at ", sink);
};

const reportTaintDetection = (s, sink) =>{
    // using warn as it creates a nice warning message with a stacktrace showing us where it came from
    if(s != null && s != undefined && s.includes(TAINT_VALUE)){
        console.warn("TAINT Pattern ", TAINT_VALUE," detected: ", s, " at ", sink);
    }
};

const report = (s, sink) =>{
    if(checkTaint){
        reportTaintDetection(s, sink);
    }else{
        reportUnsafeOperation(s, sink);
    }
}

trustedTypes.createPolicy('default',{
    createHTML: (s, sink) => {
        report(s, sink);
        return s;
    },
    createScript: (s, sink) => {
        report(s, sink);
        return s;
    },
    createScriptURL: (s, sink) =>{
        report(s, sink);
        return s;
    }
},true);