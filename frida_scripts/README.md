# frida_scripts

```
$ make
```

The packaged Python scripts that run each Typescript module are in `build/`.

## Transferring to Windows

Ensure frida is [installed](https://frida.re/docs/installation/).

```
PS> iwr -Uri "http://172.16.135.1:8001/frida_scripts/build/log_vmware_backdoor.py" -OutFile log_vmware_backdoor.py
PS> python log_vmware_backdoor.py -p vmtoolsd.exe
```