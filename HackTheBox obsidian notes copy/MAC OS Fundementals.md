Kernel : XNU --

OS Base - Darwin. FreeBSD Derivative 

GUI - Aqua 

File Manager - Finder 

Application Sandbox: By default, macOS and any apps within it utilize the concept of sandboxing, which restricts the application's access outside of the resources necessary for it to run. 

Cocoa is the application management layer and API used with macOS. It is responsible for the behavior of many built-in applications within macOS. Cocoa is also a development framework made for bringing applications into the Apple ecosystem. Things like notifications, Siri, and more, function because of Cocoa



### GUI Key Components 

Apple Menu - reference point for critical host operations, System settings. Locking the screen, shutting down  

**Finder** The component that provides desktop and file management functions 

Spotlight - Search filesystem and Icloud. Perform math conversions 

**Dock** Acts as the holder for frequently used apps 

**Launch Pad** Application menu where you can search for and launch apps

**Control Center** Manage network settings and sound display and notifications 

### Navigating OS 

Can copy and paste files in command line and GUI. No cut/paste

```shell-session
[root@htb]/Users$ defaults write com.apple.Finder AppleShowAllFiles true
[root@htb]/Users$ killall Finder
```

CMD Command to see hidden files 


**Pane Preview** Gives a brief preview of a file

Spotlight is a system-wide desktop search feature of Apple's macOS and iOS operating systems,


## System Hierarchy 
The structure mimics a standard Unix/Linux setup but also has its own context for User, Local, and System directories

![[Pasted image 20260108181752.png]]

* Local domain - Resource that are local to the  current computer annd shared among all computer users
* System domain- System software installed by apple
* User Domain -Resources specific to the users who log into the system- Home directory of the current user at run time
* Network domain - apps and documents shared among users of a local network
*

### File Structure 

![[Pasted image 20260108182049.png]]

#### Standard Directories 


Directory 	Description
/ 	Is the root filesystem and contains everything the operating system needs to complete the boot cycle. Any volumes or filesystems can be found here. Think of / as our bucket containing everything the host needs and storing them in subdirectories like /etc, /home, and /usr.

/bin 	Is our main storage point for binaries.

/dev 	Maintains our device-id files that enable the use of hardware devices attached to the 
system.

/etc 	 contains our system and application configuration files.

/sbin 	Contains all the essential and common administrative binaries we need to keep our systems running smoothly.

/tmp 	The /tmp directory is used by the operating system to store temporary files that do not need to be persistent. The files in this directory are wiped away at each reboot.

/usr 	This is one of the largest directories on our host. It contains all of the libraries we may need, applications such as FTP, SSH, and even vim.

/var 	This Is where we store our system log files, sources for our web servers, backups, and more.

/private 	Stores critical system files and caches required to operate. They are hidden in the /Private directory to ensure the standard user does not modify them.

/opt 	This is our storage point for any third-party applications or packages we install.

/cores 	Contains Core Dumps stored by MacOS that are intended for developers to troubleshoot any issues that arise.

/home 	Each user on the system has a subdirectory here for storage. Our user Desktop, Downloads, and Documents folders can be found here.

The Applications related to the system are stored at the /System/Applications directory:
'

# Nix permissions 

Perms for files are shown via an Octal or base8 numbering system- 

They are used to apply the `read, write, and execute` attributes to the contexts of `User owner, Group`

Read write execute,: User Owner . Group Owner, Others


Attribute 	Octal Value
(r) - Read 	Octal value of 4
(w) - Write 	Octal value of 2
(x) - Execute 	Octal value of 1


```shell-session
SegFaults@htb[/htb]$ ls -l  

- rw- r-- r--@  1 htb-user staff 2512910 Aug 30  2019 HTB-Wallpaper-1.png
- |_| |_| |_|   |    |       |     |      |_______|
|  |   |   |    |    |       |     |          |__ Date
|  |   |   |    |    |       |     |_____________ File Size
|  |   |   |    |    |       |___________________ Group
|  |   |   |    |    |___________________________ User
|  |   |   |    |________________________________ Number of hard links
|  |   |   |___ Permissions of others (everyone else)(read)
|  |   |_______ Permissions of the group (staff)(read)
|  |___________ Permissions of the User owner (htb-user)(read, write)
|______________ File type (- = File, d = Directory, l = Link, ... )
```


Based on the above perms and output we can see that the User owner has read write perms. The group owner  staff has read and everyone else has read. 

`UGO, which stands for User/Group/Others.` User Group Other memory device UGO


## Homebrew

[Homebrew](https://brew.sh) is a free and open-source package manager used for macOS systems and is an essential tool for developers or penetration testers using macOS. It allows easy installation of many standard tools without the hustle of manually compiling open-source tools or downloading their **requirements**

#### Installing Tools with Homebrew

Homebrew works similarly to most Linux package managers. For example, we can install `php` by running the following command:

Code: bash

```bash
brew install php
```


#### Keychain

One of the most important aspects of any system is how it handles saving our passwords. It is always recommended to use a different complex password for each application we use, which makes it impossible for us to remember all of them. This is necessary if any of our online accounts are compromised and our password is leaked; then, we will not need to change our passwords in all of our online accounts but will only need to change the password of that compromised account.


#### ZSH Config

When we start a new terminal session, the default shell gets loaded with its default configuration. The default shell is ZSH, and its default configuration is stored at `~/.zshrc`. A shell

Code: bash

```bash
# Aliases
alias ll='ls -l'
alias la='ls -la'
alias l='ls -CF'
```


Code: bash

```bash
# Archives
function extract {
  if [ -z "$1" ]; then
    echo "Usage: extract <path/file_name>.<zip|rar|bz2|gz|tar|tbz2|tgz|Z|7z|xz|ex|tar.bz2|tar.gz|tar.xz>"
  else
    if [ -f $1 ]; then
      case $1 in
        *.tar.bz2)   tar xvjf $1    ;;
        *.tar.gz)    tar xvzf $1    ;;
        *.tar.xz)    tar xvJf $1    ;;
        *.lzma)      unlzma $1      ;;
        *.bz2)       bunzip2 $1     ;;
        *.rar)       unrar x -ad $1 ;;
        *.gz)        gunzip $1      ;;
        *.tar)       tar xvf $1     ;;
        *.tbz2)      tar xvjf $1    ;;
        *.tgz)       tar xvzf $1    ;;
        *.zip)       unzip $1       ;;
        *.Z)         uncompress $1  ;;
        *.7z)        7z x $1        ;;
        *.xz)        unxz $1        ;;
        *.exe)       cabextract $1  ;;
        *)           echo "extract: '$1' - unknown archive method" ;;
      esac
    else
      echo "$1 - file does not exist"
    fi
  fi
}
```

https://ohmyz.sh/