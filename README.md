mkqcdtbootimg
=============

Copyright 2007, The Android Open Source Project  
Copyright (c) 2012, The Linux Foundation. All rights reserved.  
Copyright (c) 2013, Sony Mobile Communications AB  

mkqcdtbootimg is an extended version of the Android mkbootimg tool, found at [android.googlesource.com][]. It adds support for including one or more device tree blobs in a `QC table of device tree`, as specified in `dtbtool.txt`.

The added command line option is `--dt_dir` which takes a path that will be searched for dtb files.


Recommended usage is to add the following to your `BoardConfig.mk` and then build Android as normal
```
BOARD_CUSTOM_MKBOOTIMG := mkqcdtbootimg
BOARD_MKBOOTIMG_ARGS += --dt_dir device/x/y/dtbs
```

 [android.googlesource.com]: https://android.googlesource.com/platform/system/core/+/master/mkbootimg/
