# binddump
A small tool to list all external functions and the libraries/frameworks they come from.

## How it works
This program works by first reading the header of your Mach-O file to find the the appropriate offsets then parsing the export trie. This program was written to support 32bit, 64bit, and FAT binaries as well as little and big endian systems. I do not have many machines to test on so I have included a python script with some unit tests for you to run to make sure this will work on your system.  If you run into problems please open an issue so I can take a look at it :) 

### Building
The make file will run the unit tests by default but you are free to skip them.
```
$ make
$ ./binddump /path/to/binary
```

### Sample input/output
I would recommend piping the output into a text file as most applications will create a list larger than the terminal buffer but hey, you do you man.
```
$ ./binddump /Applications/iTunes.app/Contents/MacOS/iTunes
$ /System/Library/Frameworks/Accelerate.framework/Versions/A/Accelerate
    Non-Lazy:
      _vDSP_FFT16_copv
      _vDSP_FFT32_copv
      _vDSP_fft3_zop
      _vDSP_fft5_zop
      _vDSP_fft_zop
    Lazy:
      _vDSP_conv
      _vDSP_create_fftsetup
      _vDSP_ctoz
      _vDSP_desamp
      _vDSP_destroy_fftsetup
      _vDSP_dotpr....
```


### Todo
1. I would like to a complete refactoring and better organize the flow of the program
2. More tests
3. Add option to export data as a plist file 

I don't know if I will ever get to any of these as I don't plan on making this my legacy but either way, it is nice to have this list in case I end up bored on a plane sometime in the foreseeable future.  In any case, I am completly open to PRs if you are so inclined.

### References
https://gist.github.com/landonf/1046134

http://www.m4b.io/reverse/engineering/mach/binaries/2015/03/29/mach-binaries.html

https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/

https://opensource.apple.com/source/dyld/dyld-132.13/src/ImageLoaderMachOCompressed.cpp
