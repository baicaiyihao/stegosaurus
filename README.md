# stegosaurus

魔改自https://github.com/AngelKitty/stegosaurus  

新增pyc的大致编译版本识别以及自动遍历header长度。  
不正确的版本在进行提取的时候会报错，因此需要获取到编译时使用的python版本。

```
└─# python stegosaurus.py -x 1.pyc 
.pyc file is compiled with Python Python 3.7b5 (magic number: 3394)
Extracted payload: k5fgb2eur5sty
```

样本文件来自NUAACTF 2021 Try2FindMe题。