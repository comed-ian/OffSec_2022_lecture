var pp = (name) => Module.getExportByName(null, name)

var size = 0;

function process(ptr) {
    var alloc_size = ptr.add(-8).readPointer() & ~1;
    var req_size = size;
    size = 0;
    send({"alloc_size": alloc_size, "req_size": req_size, "ptr": ptr});
}

Interceptor.attach(pp('malloc'), {
    onEnter: (args) => {
        size = args[0];
    },
    onLeave: (retval) => {
        process(retval);
    }
})
