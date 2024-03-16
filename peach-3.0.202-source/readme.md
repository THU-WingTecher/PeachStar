# Installation

## Prerequisites

Install automake, mono package and some required packages

```shell
sudo apt-get install build-essential automake libtool libc6-dev-i386 python-pip g++-multilib mono-complete python-software-properties software-properties-common
```


## Build

```shell
clang control.c -fPIC -shared -o libpeachControl.so
./waf configure
./waf install
```

Setup environment variables:

append the following entries in the shell configuration file (`~/.bashrc`).

```shell
export PATH=/path-to-peach/:$PATH
export LD_LIBRARY_PATH=/path-to-peach/:$LD_LIBRARY_PATH
```

**or** execute the following shell (**not always safe!**):

```shell
bash setup_env.sh
```



# Running

## Create shared memory

```shell
cd /dev/shm
dd if=/dev/zero bs=10M count=1 of=$name-of-shared-memory
```

**Hint**: `$name-of-shared-memeory` should be replaced by any name you like.

##  Fuzzing

```shell
export SHM_ENV_VAR=/dev/shm/$name-of-shared-memory
mono /path-to-peach/output/linux_x86_64_release/bin/peach.exe /path-to-peach/output/linux_x86_64_release/bin/samples/HelloWorld.xml
```





# Usage

Peach* adds several more options to peach, all of these option **are not required**:

-pro: use Peach\*;

-pathp=$file-name: write path log to `file-name`;

-pathb=$file-name: write branch log to `file-name`;

-asanLog=$directory: save all the asan reports to `directory`;

-repro=$crash-directory: `directory` used to reproduce crash, for example, `./Logs-new/cyclone_test_2.xml_Default_20200408123702/Faults/ProcessExitEarly/432/`





# Pit

Monitor Example:

(1) Don't restart on each test

```xml
...

<Agent name="LocalAgent">
  <Monitor class="Process">
    <Param name="Executable" value="/path-to-under-test-program/" />
    <Param name="Arguments" value="...options..." />
    <Param name="RestartOnEachTest" value="false" />
    <Param name="FaultOnEarlyExit" value="true" />
  </Monitor>
</Agent>

<Test name="Default">
  <Agent ref="LocalAgent" />
  ...
</Test>
```

(2) Restart on each test

```xml
...

<Agent name="LocalAgent">
  <Monitor class="Process">
    <Param name="Executable" value="/path-to-under-test-program/" />
    <Param name="Arguments" value="...options..." />
    <Param name="RestartOnEachTest" value="true" />
    <Param name="FaultOnEarlyExit" value="false" />
  </Monitor>
</Agent>

<Test name="Default">
  <Agent ref="LocalAgent" />
  ...
</Test>
```



