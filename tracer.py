import sys
import frida

def on_message(message, data):    
    req_size = int(message["payload"]["req_size"], 16)
    alloc_size = message["payload"]["alloc_size"]
    ptr = int(message["payload"]["ptr"], 16)

    print("Buffer allocated at " + hex(ptr))
    print("Requested size: " + hex(req_size), end="; ")
    print("Allocated size: " + hex(alloc_size), end="\n\n")

    if req_size == 0: 
        print("!!!! requested 0x0 bytes and returned a valid ptr: " + hex(ptr))
        exit(0)

def run():
    manager = frida.get_device_manager()
    dev = manager.get_device("local")

    pid = dev.spawn(["/home/comedian/Documents/codeql-home/binutils-gdb/binutils/objdump", 
        "-g", "/home/comedian/Documents/codeql-home/binutils-gdb/binutils/objdump_crash"])
    sess = dev.attach(pid)
    src = open('./agent.js', 'r').read()
    script = sess.create_script(src)
    script.load()
    script.on('message', on_message)
    dev.resume(pid)

    while True:
        sys.stdin.read(1)

if __name__=='__main__':
    run()
